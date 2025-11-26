#!/usr/bin/env python3 -u

import argparse
import contextlib
import fcntl
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    psutil = None

PROC_NET_DEV = "/proc/net/dev"
SYSFS_NET_PATH = "/sys/class/net"
BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"]
DEFAULT_UNITS = ["B", "KB", "MB", "GB", "TB"]
MAX_FILE_SIZE = 8192
MAX_CACHE_SIZE = 1000
MAX_HISTORY_SIZE = 1000


@dataclass
class MonitorConfig:
    interval: float = 1.0
    cache_ttl: float = 5.0
    max_interfaces: int = 100
    show_loopback: bool = True
    show_inactive: bool = False
    precision: int = 1
    counter_bits: int = 64
    units: str = "binary"
    show_processes: bool = False


class Colors:
    RESET = "\033[0m"
    GREY = "\033[38;5;250m"
    SEPIA = "\033[38;5;130m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"

    @classmethod
    def disable(cls) -> None:
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, "")


class SignalHandler:
    def __init__(self):
        self.shutdown_requested = False
        self.original_handlers = {}
        self._lock = threading.Lock()
        
        for sig in [signal.SIGINT, signal.SIGTERM]:
            try:
                self.original_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass
    
    def _signal_handler(self, signum: int, frame) -> None:
        with self._lock:
            self.shutdown_requested = True
        
    def restore_handlers(self):
        for signum, handler in self.original_handlers.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass


@dataclass
class InterfaceTraffic:
    name: str
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errs: int = 0
    tx_errs: int = 0
    rx_drop: int = 0
    tx_drop: int = 0
    mtu: Optional[int] = None
    state: str = "unknown"
    ipv4_addr: Optional[str] = None
    ipv6_addrs: List[str] = field(default_factory=list)
    speed: Optional[int] = None
    duplex: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.rx_bytes > 0 or self.tx_bytes > 0 or self.rx_packets > 0 or self.tx_packets > 0

    @property
    def is_up(self) -> bool:
        return self.state == "up"
    
    @property
    def total_bytes(self) -> int:
        return self.rx_bytes + self.tx_bytes
    
    @property
    def total_packets(self) -> int:
        return self.rx_packets + self.tx_packets


class RateCalculator:
    def __init__(self, config: MonitorConfig):
        self.config = config
    
    def calculate_rate(self, current: int, previous: int, interval: float) -> float:
        if interval <= 0:
            return 0.0
            
        try:
            if current >= previous:
                return (current - previous) / interval
            else:
                max_count = 2**self.config.counter_bits - 1
                if max_count <= 0:
                    max_count = 2**64 - 1
                return ((max_count - previous) + current + 1) / interval
        except (ZeroDivisionError, OverflowError):
            return 0.0
    
    def calculate_all_rates(self, current: InterfaceTraffic, previous: InterfaceTraffic, interval: float) -> Dict[str, float]:
        return {
            'rx_bytes_sec': self.calculate_rate(current.rx_bytes, previous.rx_bytes, interval),
            'tx_bytes_sec': self.calculate_rate(current.tx_bytes, previous.tx_bytes, interval),
            'rx_packets_sec': self.calculate_rate(current.rx_packets, previous.rx_packets, interval),
            'tx_packets_sec': self.calculate_rate(current.tx_packets, previous.tx_packets, interval),
        }


def with_retry(max_attempts: int = 3, delay: float = 0.1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (OSError, IOError, FileNotFoundError) as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(delay * (2 ** attempt))
            raise last_exception
        return wrapper
    return decorator


def validate_config(config: MonitorConfig) -> List[str]:
    errors = []
    if config.interval < 0.1 or config.interval > 3600:
        errors.append("Interval must be between 0.1 and 3600 seconds")
    if config.max_interfaces < 1 or config.max_interfaces > 1000:
        errors.append("Max interfaces must be between 1 and 1000")
    if config.cache_ttl < 0:
        errors.append("Cache TTL must be positive")
    if config.units not in ["binary", "decimal"]:
        errors.append("Units must be 'binary' or 'decimal'")
    if config.counter_bits not in [32, 64]:
        errors.append("Counter bits must be 32 or 64")
    if config.precision < 0 or config.precision > 6:
        errors.append("Precision must be between 0 and 6")
    return errors


class LRUCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: Dict[str, Tuple[object, float]] = {}
        self._lock = threading.Lock()
    
    def get(self, key: str) -> Optional[object]:
        with self._lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                # Move to end (most recently used)
                del self.cache[key]
                self.cache[key] = (value, timestamp)
                return value
        return None
    
    def set(self, key: str, value: object, timestamp: float = None):
        if timestamp is None:
            timestamp = time.time()
        with self._lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                # Remove least recently used
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
            self.cache[key] = (value, timestamp)
    
    def cleanup_old(self, max_age: float):
        cutoff = time.time() - max_age
        with self._lock:
            keys_to_remove = [k for k, (_, ts) in self.cache.items() if ts < cutoff]
            for key in keys_to_remove:
                del self.cache[key]


class NetworkMonitor:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.rate_calculator = RateCalculator(config)
        self._lock = RLock()
        self._ipv6_cache = LRUCache(max_size=MAX_CACHE_SIZE)
        self._mtu_cache = LRUCache(max_size=MAX_CACHE_SIZE)
        self._state_cache = LRUCache(max_size=MAX_CACHE_SIZE)
        self._speed_cache = LRUCache(max_size=MAX_CACHE_SIZE)
        self._duplex_cache = LRUCache(max_size=MAX_CACHE_SIZE)
        self._interface_cache: Optional[List[str]] = None
        self._interface_cache_time: float = 0
        self._prev_traffic: Dict[str, InterfaceTraffic] = {}
        self._rate_history: Dict[str, List[Tuple[float, float, float]]] = {}
        self._static_info_cache: Dict[str, Dict] = {}
        self._static_cache_time: float = 0

    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        
    def cleanup(self):
        with self._lock:
            self._ipv6_cache = LRUCache(max_size=MAX_CACHE_SIZE)
            self._mtu_cache = LRUCache(max_size=MAX_CACHE_SIZE)
            self._state_cache = LRUCache(max_size=MAX_CACHE_SIZE)
            self._speed_cache = LRUCache(max_size=MAX_CACHE_SIZE)
            self._duplex_cache = LRUCache(max_size=MAX_CACHE_SIZE)
            self._interface_cache = None
            self._prev_traffic.clear()
            self._rate_history.clear()
            self._static_info_cache.clear()

    def get_divisor(self) -> int:
        return 1000 if self.config.units == "decimal" else 1024

    def get_units(self) -> List[str]:
        return DEFAULT_UNITS if self.config.units == "decimal" else BYTE_UNITS

    def format_bytes(self, size: int) -> str:
        if size == 0:
            return "0B"
            
        divisor = self.get_divisor()
        units = self.get_units()
        unit_idx = 0
        readable = float(size)
        
        while readable >= divisor and unit_idx < len(units) - 1:
            readable /= divisor
            unit_idx += 1
        
        if unit_idx == 0:
            return f"{readable:.0f}{units[unit_idx]}"
        elif readable < 10:
            return f"{readable:.{self.config.precision}f}{units[unit_idx]}"
        else:
            return f"{readable:.{self.config.precision}f}{units[unit_idx]}"

    def format_rate_precise(self, bytes_per_sec: float) -> str:
        if bytes_per_sec <= 0:
            return "0B/s"
        
        divisor = self.get_divisor()
        units = self.get_units()
        unit_idx = 0
        readable = float(bytes_per_sec)
        
        while readable >= divisor and unit_idx < len(units) - 1:
            readable /= divisor
            unit_idx += 1
        
        if unit_idx == 0:
            return f"{readable:.0f}{units[unit_idx]}/s"
        elif readable < 10:
            return f"{readable:.{self.config.precision}f}{units[unit_idx]}/s"
        else:
            return f"{readable:.{self.config.precision}f}{units[unit_idx]}/s"

    def safe_interface_name(self, name: str) -> bool:
        if not name or not isinstance(name, str):
            return False
        if any(c in name for c in ['/', '\\', '..', '\0']):
            return False
        return all(c.isalnum() or c in ("-", "_", ".", ":") for c in name) and len(name) <= 64

    def validate_sysfs_path(self, file_path: str) -> bool:
        try:
            normalized_path = os.path.normpath(file_path)
            if not normalized_path.startswith(SYSFS_NET_PATH):
                return False
            
            relative_path = os.path.relpath(normalized_path, SYSFS_NET_PATH)
            if relative_path.startswith('..') or os.path.isabs(relative_path):
                return False
            
            path_parts = relative_path.split(os.sep)
            if len(path_parts) < 1:
                return False
            
            iface_name = path_parts[0]
            if not self.safe_interface_name(iface_name):
                return False
            
            if len(path_parts) > 1:
                filename = path_parts[1]
                allowed_files = [
                    'tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets',
                    'tx_errors', 'rx_errors', 'tx_dropped', 'rx_dropped',
                    'operstate', 'carrier', 'speed', 'mtu', 'duplex'
                ]
                if filename not in allowed_files:
                    return False
            
            return True
        except (ValueError, OSError):
            return False

    @with_retry(max_attempts=3)
    def _read_sysfs_file(self, interface: str, filename: str) -> Optional[str]:
        if not self.safe_interface_name(interface) or not self.safe_interface_name(filename):
            return None
        
        file_path = os.path.join(SYSFS_NET_PATH, interface, filename)
        
        if not self.validate_sysfs_path(file_path):
            return None
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                return None
                
            with open(file_path, 'r') as f:
                return f.read().strip()
        except (OSError, IOError, PermissionError, FileNotFoundError):
            return None

    def _read_interface_state(self, interface: str) -> str:
        state = self._read_sysfs_file(interface, "operstate")
        return state.lower() if state else "unknown"

    def get_interface_state(self, interface: str) -> str:
        cached = self._state_cache.get(interface)
        if cached is not None:
            return cached
        
        state = self._read_interface_state(interface)
        self._state_cache.set(interface, state)
        return state

    def _read_interface_speed(self, interface: str) -> Optional[int]:
        speed_str = self._read_sysfs_file(interface, "speed")
        if speed_str:
            try:
                return int(speed_str)
            except ValueError:
                pass
        return None

    def get_interface_speed(self, interface: str) -> Optional[int]:
        cached = self._speed_cache.get(interface)
        if cached is not None:
            return cached
        
        speed = self._read_interface_speed(interface)
        self._speed_cache.set(interface, speed)
        return speed

    def _read_interface_duplex(self, interface: str) -> Optional[str]:
        duplex = self._read_sysfs_file(interface, "duplex")
        return duplex.lower() if duplex else None

    def get_interface_duplex(self, interface: str) -> Optional[str]:
        cached = self._duplex_cache.get(interface)
        if cached is not None:
            return cached
        
        duplex = self._read_interface_duplex(interface)
        self._duplex_cache.set(interface, duplex)
        return duplex

    def get_available_interfaces(self) -> List[str]:
        now = time.time()
        with self._lock:
            if (self._interface_cache is not None and 
                (now - self._interface_cache_time) < self.config.cache_ttl):
                return self._interface_cache[:]  # Return a copy
        
        try:
            interfaces = []
            for iface in os.listdir(SYSFS_NET_PATH):
                iface_path = os.path.join(SYSFS_NET_PATH, iface)
                if (os.path.isdir(iface_path) and 
                    self.safe_interface_name(iface)):
                    
                    if not self.config.show_loopback and iface == "lo":
                        continue
                    
                    operstate = self.get_interface_state(iface)
                    if operstate == "down" and not self.config.show_inactive:
                        continue
                    
                    interfaces.append(iface)
            
            with self._lock:
                self._interface_cache = sorted(interfaces)
                self._interface_cache_time = now
                return self._interface_cache[:]  # Return a copy
        except (OSError, FileNotFoundError):
            return self._interface_cache[:] if self._interface_cache else []

    def validate_interfaces(self, requested_ifaces: Optional[List[str]]) -> List[str]:
        available = self.get_available_interfaces()
        if not requested_ifaces:
            return available
        
        valid_ifaces = [iface for iface in requested_ifaces if iface in available]
        invalid_ifaces = set(requested_ifaces) - set(valid_ifaces)
        
        if invalid_ifaces:
            print(f"{Colors.RED}Warning: Invalid interfaces: {sorted(invalid_ifaces)}{Colors.RESET}", 
                  file=sys.stderr)
        
        return valid_ifaces

    def _get_mtu_uncached(self, interface: str) -> Optional[int]:
        if not self.safe_interface_name(interface):
            return None
            
        try:
            mtu_str = self._read_sysfs_file(interface, "mtu")
            if mtu_str:
                return int(mtu_str)
        except ValueError:
            pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifr = struct.pack("16sI", interface.encode("utf-8")[:15], 0)
                mtu_data = fcntl.ioctl(s.fileno(), 0x8921, ifr)
                return struct.unpack("16sI", mtu_data)[1]
        except (OSError, struct.error):
            return None

    def get_mtu_cached(self, interface: str) -> Optional[int]:
        cached = self._mtu_cache.get(interface)
        if cached is not None:
            return cached
        
        mtu = self._get_mtu_uncached(interface)
        self._mtu_cache.set(interface, mtu)
        return mtu

    def get_ipv4_info(self, interface: str) -> Optional[str]:
        if not self.safe_interface_name(interface):
            return None
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifr = struct.pack('256s', interface.encode('utf-8')[:15])
                try:
                    result = fcntl.ioctl(s.fileno(), 0x8915, ifr)  # SIOCGIFADDR
                    ip_addr = socket.inet_ntoa(result[20:24])
                    
                    result = fcntl.ioctl(s.fileno(), 0x891b, ifr)  # SIOCGIFNETMASK
                    netmask = socket.inet_ntoa(result[20:24])
                    prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                    
                    return f"{ip_addr}/{prefix}"
                except OSError:
                    return None
                
        except Exception:
            return None

    def _get_all_ipv6_info_uncached(self) -> Dict[str, List[str]]:
        ipv6_map: Dict[str, List[str]] = {}
        try:
            with subprocess.Popen(["ip", "-6", "addr", "show"],
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.DEVNULL,  # Suppress stderr
                                text=True,
                                shell=False) as proc:
                try:
                    stdout, _ = proc.communicate(timeout=5)
                    if proc.returncode == 0 and stdout:
                        iface = None
                        for line in stdout.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            if line[0].isdigit() and ":" in line:
                                iface = line.split(":")[1].strip().split("@")[0]
                                if iface and not self.safe_interface_name(iface):
                                    iface = None
                                continue
                            if iface and "inet6" in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    addr_parts = parts[1].split("/")
                                    if len(addr_parts) == 2:
                                        addr, prefix = addr_parts
                                        scope = "global" if "scope global" in line else "link"
                                        ipv6_map.setdefault(iface, []).append(f"{addr}/{prefix} ({scope})")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        return ipv6_map

    def get_all_ipv6_info_cached(self) -> Dict[str, List[str]]:
        now = time.time()
        cached = self._ipv6_cache.get("all_ipv6_info")
        if cached is not None:
            return cached
        
        ipv6_map = self._get_all_ipv6_info_uncached()
        self._ipv6_cache.set("all_ipv6_info", ipv6_map, timestamp=now)
        return ipv6_map

    def _refresh_static_cache(self):
        static_info = {}
        for iface in self.get_available_interfaces():
            static_info[iface] = {
                'state': self.get_interface_state(iface),
                'mtu': self.get_mtu_cached(iface),
                'speed': self.get_interface_speed(iface),
                'duplex': self.get_interface_duplex(iface),
                'addrs': self.get_interface_addrs(iface)
            }
        self._static_info_cache = static_info
        self._static_cache_time = time.time()

    def get_static_interface_info(self, interface: str) -> Dict:
        now = time.time()
        if now - self._static_cache_time > 30:
            self._refresh_static_cache()
        return self._static_info_cache.get(interface, {})

    def get_interface_addrs(self, interface: str) -> Dict[str, List[str]]:
        addrs = {"ipv4": [], "ipv6": []}
        
        ipv4 = self.get_ipv4_info(interface)
        if ipv4:
            addrs["ipv4"].append(ipv4)
        
        ipv6_map = self.get_all_ipv6_info_cached()
        if self.safe_interface_name(interface) and interface in ipv6_map:
            addrs["ipv6"].extend(ipv6_map[interface])
        
        return addrs

    def format_addrs_string(self, addrs: Dict[str, List[str]]) -> str:
        parts = []
        if addrs["ipv4"]:
            parts.append(f"IPv4: {', '.join(addrs['ipv4'])}")
        if addrs["ipv6"]:
            ipv6_display = addrs["ipv6"][:2]
            if len(addrs["ipv6"]) > 2:
                ipv6_display.append(f"... (+{len(addrs['ipv6']) - 2} more)")
            parts.append(f"IPv6: {', '.join(ipv6_display)}")
        return "; ".join(parts) if parts else "No addresses"

    def update_rate_history(self, interface: str, rx_rate: float, tx_rate: float):
        with self._lock:
            if interface not in self._rate_history:
                self._rate_history[interface] = []
            
            self._rate_history[interface].append((rx_rate, tx_rate, time.time()))
            
            if len(self._rate_history[interface]) > MAX_HISTORY_SIZE:
                self._rate_history[interface] = self._rate_history[interface][-MAX_HISTORY_SIZE:]
            
            if len(self._rate_history) > MAX_CACHE_SIZE:
                current_ifaces = set(self.get_available_interfaces())
                stale_ifaces = set(self._rate_history.keys()) - current_ifaces
                for stale in stale_ifaces:
                    if stale in self._rate_history:
                        del self._rate_history[stale]

    def cleanup_old_history(self, max_age: float = 300):
        cutoff = time.time() - max_age
        with self._lock:
            for iface in list(self._rate_history.keys()):
                self._rate_history[iface] = [
                    entry for entry in self._rate_history[iface] 
                    if entry[2] > cutoff
                ]
                if not self._rate_history[iface]:
                    del self._rate_history[iface]

    def get_avg_rates(self, interface: str) -> Tuple[float, float]:
        with self._lock:
            if interface not in self._rate_history or not self._rate_history[interface]:
                return 0.0, 0.0
            
            rx_rates = [rate[0] for rate in self._rate_history[interface]]
            tx_rates = [rate[1] for rate in self._rate_history[iface]]
            
            return sum(rx_rates) / len(rx_rates), sum(tx_rates) / len(tx_rates)

    def get_network_processes(self) -> List[Dict]:
        if not psutil:
            return []
        try:
            network_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    connections = proc.info['connections']
                    if connections:
                        network_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'connections': len(connections)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return sorted(network_processes, key=lambda x: x['connections'], reverse=True)[:10]
        except Exception:
            return []


def read_proc_net_dev_safe(max_lines: int = 1000) -> List[str]:
    lines = []
    try:
        file_size = os.path.getsize(PROC_NET_DEV)
        if file_size > MAX_FILE_SIZE * 10:
            return lines
            
        with open(PROC_NET_DEV, 'r') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                if line.strip() and not line.startswith('Inter-face'):
                    lines.append(line.strip())
    except (OSError, IOError, FileNotFoundError):
        pass
    return lines


@with_retry(max_attempts=3)
def parse_proc_net_dev(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None, include_static: bool = True) -> Dict[str, InterfaceTraffic]:
    stats: Dict[str, InterfaceTraffic] = {}
    
    if not os.path.exists(PROC_NET_DEV):
        return stats

    lines = read_proc_net_dev_safe()
    valid_ifaces = monitor.validate_interfaces(filter_ifaces)
    
    for line in lines:
        parts = line.split()
        if len(parts) < 17:
            continue
            
        iface = parts[0].rstrip(":")
        if valid_ifaces and iface not in valid_ifaces:
            continue
            
        try:
            rx_bytes = int(parts[1])
            rx_packets = int(parts[2])
            rx_errs = int(parts[3])
            rx_drop = int(parts[4])
            tx_bytes = int(parts[9])
            tx_packets = int(parts[10])
            tx_errs = int(parts[11])
            tx_drop = int(parts[12])
        except (ValueError, IndexError):
            continue
        
        if not monitor.config.show_inactive and rx_bytes == 0 and tx_bytes == 0:
            continue
        
        if include_static:
            static_info = monitor.get_static_interface_info(iface)
            state = static_info.get('state', 'unknown')
            mtu = static_info.get('mtu')
            speed = static_info.get('speed')
            duplex = static_info.get('duplex')
            addrs = static_info.get('addrs', {'ipv4': [], 'ipv6': []})
        else:
            state = 'unknown'
            mtu = None
            speed = None
            duplex = None
            addrs = {'ipv4': [], 'ipv6': []}
        
        traffic = InterfaceTraffic(
            name=iface,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            rx_packets=rx_packets,
            tx_packets=tx_packets,
            rx_errs=rx_errs,
            tx_errs=tx_errs,
            rx_drop=rx_drop,
            tx_drop=tx_drop,
            mtu=mtu,
            state=state,
            ipv4_addr=addrs["ipv4"][0] if addrs["ipv4"] else None,
            ipv6_addrs=addrs["ipv6"],
            speed=speed,
            duplex=duplex
        )
        
        stats[iface] = traffic
        
        if len(stats) >= monitor.config.max_interfaces:
            break
            
    return stats


def display_network_info(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    print(f"{Colors.BLUE}Network Interface Information:{Colors.RESET}")
    valid_ifaces = monitor.validate_interfaces(filter_ifaces)
    
    if not valid_ifaces:
        print(f"{Colors.GREY}No interfaces found.{Colors.RESET}")
        return
    
    for iface in valid_ifaces:
        static_info = monitor.get_static_interface_info(iface)
        state = static_info.get('state', 'unknown')
        state_color = Colors.GREEN if state == "up" else Colors.RED
        mtu = static_info.get('mtu')
        addrs = static_info.get('addrs', {'ipv4': [], 'ipv6': []})
        speed = static_info.get('speed')
        duplex = static_info.get('duplex')
        
        print(f"\n{Colors.SEPIA}{iface}{Colors.RESET} [{state_color}{state}{Colors.RESET}]")
        
        if speed:
            duplex_str = f", {duplex}" if duplex else ""
            print(f"  Speed: {speed} Mbps{duplex_str}")
            
        if mtu:
            print(f"  MTU: {mtu}")
            
        print(f"  Addresses: {monitor.format_addrs_string(addrs)}")


def display_traffic_stats(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_proc_net_dev(monitor, filter_ifaces)
    if not stats:
        print(f"{Colors.GREY}No traffic statistics available.{Colors.RESET}")
        return
        
    print(f"{Colors.BLUE}\nTraffic Statistics:{Colors.RESET}")
    
    sorted_stats = sorted(stats.items(), key=lambda x: x[1].total_bytes, reverse=True)
    
    for iface, traffic in sorted_stats:
        state_color = Colors.GREEN if traffic.is_up else Colors.RED
        speed_info = f" ({traffic.speed} Mbps)" if traffic.speed else ""
        
        print(f"\n{Colors.SEPIA}{iface:<12}{Colors.RESET} [{state_color}{traffic.state}{Colors.RESET}]{speed_info}")
        print(f"  RX: {Colors.GREEN}{monitor.format_bytes(traffic.rx_bytes):<12}{Colors.RESET} "
              f"{Colors.GREY}({traffic.rx_packets} pkts, {traffic.rx_errs} errs, {traffic.rx_drop} drop){Colors.RESET}")
        print(f"  TX: {Colors.YELLOW}{monitor.format_bytes(traffic.tx_bytes):<12}{Colors.RESET} "
              f"{Colors.GREY}({traffic.tx_packets} pkts, {traffic.tx_errs} errs, {traffic.tx_drop} drop){Colors.RESET}")
        
        if traffic.is_active:
            total = monitor.format_bytes(traffic.total_bytes)
            print(f"  Total: {Colors.CYAN}{total}{Colors.RESET} "
                  f"({traffic.total_packets} total packets)")


def clear_screen() -> None:
    if os.name == 'posix':
        sys.stdout.write("\033[H\033[J")
    else:
        os.system('cls' if os.name == 'nt' else 'clear')
    sys.stdout.flush()


def watch_mode_improved(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]], interval: float) -> None:
    if interval < 0.01:
        print(f"{Colors.RED}Interval too small: {interval}s{Colors.RESET}")
        return
        
    prev_stats: Dict[str, InterfaceTraffic] = {}
    start_time = time.time()
    update_count = 0
    signal_handler = SignalHandler()
    
    try:
        while not signal_handler.shutdown_requested:
            clear_screen()
            current_time = time.time()
            elapsed_total = current_time - start_time
            
            print(f"{Colors.BLUE}Live Network Traffic Monitor{Colors.RESET}")
            print(f"{Colors.GREY}Interval: {interval}s | Uptime: {elapsed_total:.0f}s | Updates: {update_count}{Colors.RESET}\n")
            
            curr_stats = parse_proc_net_dev(monitor, filter_ifaces, include_static=False)
            
            for iface, now in curr_stats.items():
                if iface in prev_stats:
                    old = prev_stats[iface]
                    rates = monitor.rate_calculator.calculate_all_rates(now, old, interval)
                    monitor.update_rate_history(iface, rates['rx_bytes_sec'], rates['tx_bytes_sec'])
            
            # Sort by current RX rate if available, otherwise by interface name
            sorted_stats = sorted(curr_stats.items(), 
                                key=lambda x: (monitor.rate_calculator.calculate_rate(
                                    x[1].rx_bytes, 
                                    prev_stats[x[0]].rx_bytes if x[0] in prev_stats else 0, 
                                    interval
                                ) if x[0] in prev_stats else 0, x[0]), 
                                reverse=True)
            
            for iface, now in sorted_stats:
                state_color = Colors.GREEN if now.is_up else Colors.RED
                
                line_parts = [f"{Colors.SEPIA}{iface:<12}{Colors.RESET} [{state_color}{now.state:<5}{Colors.RESET}]"]
                
                if iface in prev_stats:
                    rx_rate = monitor.rate_calculator.calculate_rate(now.rx_bytes, prev_stats[iface].rx_bytes, interval)
                    tx_rate = monitor.rate_calculator.calculate_rate(now.tx_bytes, prev_stats[iface].tx_bytes, interval)
                    avg_rx, avg_tx = monitor.get_avg_rates(iface)
                    
                    line_parts.extend([
                        f"RX: {Colors.GREEN}{monitor.format_rate_precise(rx_rate):<12}{Colors.RESET}",
                        f"TX: {Colors.YELLOW}{monitor.format_rate_precise(tx_rate):<12}{Colors.RESET}",
                        f"Avg: {Colors.CYAN}{monitor.format_rate_precise(avg_rx)}/{monitor.format_rate_precise(avg_tx)}{Colors.RESET}"
                    ])
                else:
                    line_parts.extend([
                        f"RX: {Colors.GREEN}{monitor.format_bytes(now.rx_bytes):<12}{Colors.RESET}",
                        f"TX: {Colors.YELLOW}{monitor.format_bytes(now.tx_bytes):<12}{Colors.RESET}",
                        f"{Colors.GREY}(initial){Colors.RESET}"
                    ])
                
                print(" ".join(line_parts))
            
            if not curr_stats:
                print(f"{Colors.GREY}No active interfaces to monitor.{Colors.RESET}")
            
            active_count = sum(1 for traffic in curr_stats.values() if traffic.is_active)
            total_rx = sum(t.rx_bytes for t in curr_stats.values())
            total_tx = sum(t.tx_bytes for t in curr_stats.values())
            
            print(f"\n{Colors.GREY}[Ctrl+C to stop] | "
                  f"Interfaces: {len(curr_stats)} (active: {active_count}) | "
                  f"Total: RX{monitor.format_bytes(total_rx)} TX{monitor.format_bytes(total_tx)} | "
                  f"{time.strftime('%H:%M:%S')}{Colors.RESET}")
            
            prev_stats = curr_stats
            update_count += 1
            
            if update_count % 10 == 0:
                monitor.cleanup_old_history()
            
            sleep_remaining = interval
            while sleep_remaining > 0 and not signal_handler.shutdown_requested:
                time.sleep(min(0.1, sleep_remaining))
                sleep_remaining -= 0.1
    except KeyboardInterrupt:
        print(f"\n{Colors.GREY}Monitoring stopped.{Colors.RESET}")
    finally:
        signal_handler.restore_handlers()


def main():
    parser = argparse.ArgumentParser(description="Network interface monitor")
    parser.add_argument("interfaces", nargs="*", help="Specific interfaces to monitor")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Update interval in seconds")
    parser.add_argument("-w", "--watch", action="store_true", help="Watch mode")
    parser.add_argument("--info", action="store_true", help="Show interface information")
    parser.add_argument("--stats", action="store_true", help="Show traffic statistics")
    parser.add_argument("--no-loopback", action="store_true", help="Hide loopback interfaces")
    parser.add_argument("--show-inactive", action="store_true", help="Show inactive interfaces")
    parser.add_argument("--units", choices=["binary", "decimal"], default="binary", help="Units for display")
    parser.add_argument("--precision", type=int, default=1, help="Decimal precision")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    config = MonitorConfig(
        interval=args.interval,
        show_loopback=not args.no_loopback,
        show_inactive=args.show_inactive,
        units=args.units,
        precision=args.precision
    )
    
    errors = validate_config(config)
    if errors:
        for error in errors:
            print(f"{Colors.RED}Error: {error}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    with NetworkMonitor(config) as monitor:
        if args.info:
            display_network_info(monitor, args.interfaces)
        elif args.stats:
            display_traffic_stats(monitor, args.interfaces)
        elif args.watch:
            watch_mode_improved(monitor, args.interfaces, args.interval)
        else:
            # Default: show both info and stats
            display_network_info(monitor, args.interfaces)
            display_traffic_stats(monitor, args.interfaces)


if __name__ == "__main__":
    main()
