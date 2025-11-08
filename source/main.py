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


def with_retry(max_attempts: int = 3, delay: float = 0.1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (OSError, IOError) as e:
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
    if config.max_interfaces < 1 or config.max_interfaces > 10000:
        errors.append("Max interfaces must be between 1 and 10000")
    if config.cache_ttl < 0:
        errors.append("Cache TTL must be positive")
    if config.units not in ["binary", "decimal"]:
        errors.append("Units must be 'binary' or 'decimal'")
    if config.counter_bits not in [32, 64]:
        errors.append("Counter bits must be 32 or 64")
    return errors


class NetworkMonitor:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self._lock = RLock()
        self._ipv6_cache: Optional[Dict[str, List[str]]] = None
        self._ipv6_cache_time: float = 0
        self._mtu_cache: Dict[str, Optional[int]] = {}
        self._state_cache: Dict[str, str] = {}
        self._speed_cache: Dict[str, Optional[int]] = {}
        self._duplex_cache: Dict[str, Optional[str]] = {}
        self._interface_cache: Optional[List[str]] = None
        self._interface_cache_time: float = 0
        self._prev_traffic: Dict[str, InterfaceTraffic] = {}
        self._rate_history: Dict[str, List[Tuple[float, float]]] = {}

    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        
    def cleanup(self):
        with self._lock:
            if self._ipv6_cache is not None:
                self._ipv6_cache.clear()
            self._mtu_cache.clear()
            self._state_cache.clear()
            self._speed_cache.clear()
            self._duplex_cache.clear()
            self._interface_cache = None
            self._prev_traffic.clear()
            self._rate_history.clear()

    def get_divisor(self) -> int:
        return 1000 if self.config.units == "decimal" else 1024

    def get_units(self) -> List[str]:
        return DEFAULT_UNITS if self.config.units == "decimal" else BYTE_UNITS

    def format_bytes(self, size: int) -> str:
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
            return f"{readable:.2f}{units[unit_idx]}"
        else:
            return f"{readable:.1f}{units[unit_idx]}"

    def format_rate_precise(self, bytes_per_sec: float) -> str:
        if bytes_per_sec < 0:
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
            return f"{readable:.2f}{units[unit_idx]}/s"
        else:
            return f"{readable:.1f}{units[unit_idx]}/s"

    def safe_interface_name(self, name: str) -> bool:
        if not name or not isinstance(name, str):
            return False
        if any(c in name for c in ['/', '\\', '..', '\0']):
            return False
        return all(c.isalnum() or c in ("-", "_", ".", ":") for c in name) and len(name) <= 64

    @with_retry(max_attempts=3)
    def _read_sysfs_file(self, interface: str, filename: str) -> Optional[str]:
        if not self.safe_interface_name(interface) or not self.safe_interface_name(filename):
            return None
        
        file_path = os.path.join(SYSFS_NET_PATH, interface, filename)
        
        if not file_path.startswith(SYSFS_NET_PATH):
            return None
            
        try:
            with open(file_path, 'r') as f:
                return f.read().strip()
        except (OSError, IOError, PermissionError):
            return None

    def _read_interface_state(self, interface: str) -> str:
        state = self._read_sysfs_file(interface, "operstate")
        return state.lower() if state else "unknown"

    def get_interface_state(self, interface: str) -> str:
        with self._lock:
            if interface in self._state_cache:
                return self._state_cache[interface]
        
        state = self._read_interface_state(interface)
        
        with self._lock:
            self._state_cache[interface] = state
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
        with self._lock:
            if interface in self._speed_cache:
                return self._speed_cache[interface]
        
        speed = self._read_interface_speed(interface)
        
        with self._lock:
            self._speed_cache[interface] = speed
            return speed

    def _read_interface_duplex(self, interface: str) -> Optional[str]:
        duplex = self._read_sysfs_file(interface, "duplex")
        return duplex.lower() if duplex else None

    def get_interface_duplex(self, interface: str) -> Optional[str]:
        with self._lock:
            if interface in self._duplex_cache:
                return self._duplex_cache[interface]
        
        duplex = self._read_interface_duplex(interface)
        
        with self._lock:
            self._duplex_cache[interface] = duplex
            return duplex

    def get_available_interfaces(self) -> List[str]:
        now = time.time()
        with self._lock:
            if (self._interface_cache is not None and 
                (now - self._interface_cache_time) < self.config.cache_ttl):
                return self._interface_cache
        
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
                return self._interface_cache
        except OSError:
            return []

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
        with self._lock:
            if interface in self._mtu_cache:
                return self._mtu_cache[interface]
        
        mtu = self._get_mtu_uncached(interface)
        
        with self._lock:
            self._mtu_cache[interface] = mtu
            return mtu

    def get_ipv4_info(self, interface: str) -> Optional[str]:
        if not self.safe_interface_name(interface):
            return None
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifr = struct.pack('16sH14s', interface.encode('utf-8')[:15], socket.AF_INET, b'\x00'*14)
                try:
                    result = fcntl.ioctl(s.fileno(), 0x8915, ifr)
                    ip_addr = socket.inet_ntoa(result[20:24])
                    
                    result = fcntl.ioctl(s.fileno(), 0x891b, ifr)
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
            proc = subprocess.run(
                ["ip", "-6", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False
            )
            if proc.returncode != 0 or not proc.stdout:
                return ipv6_map

            iface = None
            for line in proc.stdout.splitlines():
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
                    addr, prefix = parts[1].split("/")
                    scope = "global" if "scope global" in line else "link"
                    ipv6_map.setdefault(iface, []).append(f"{addr}/{prefix} ({scope})")

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ipv6_map

    def get_all_ipv6_info_cached(self) -> Dict[str, List[str]]:
        now = time.time()
        with self._lock:
            if (self._ipv6_cache is not None and 
                (now - self._ipv6_cache_time) < self.config.cache_ttl):
                return self._ipv6_cache
        
        ipv6_map = self._get_all_ipv6_info_uncached()
        
        with self._lock:
            self._ipv6_cache = ipv6_map
            self._ipv6_cache_time = now
            return self._ipv6_cache

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

    def update_rate_history(self, interface: str, rx_rate: float, tx_rate: float):
        with self._lock:
            if interface not in self._rate_history:
                self._rate_history[interface] = []
            
            self._rate_history[interface].append((rx_rate, tx_rate))
            
            max_history = 60
            if len(self._rate_history[interface]) > max_history:
                self._rate_history[interface] = self._rate_history[interface][-max_history:]
            
            if len(self._rate_history) > 100:
                current_ifaces = set(self.get_available_interfaces())
                stale_ifaces = set(self._rate_history.keys()) - current_ifaces
                for stale in stale_ifaces:
                    if stale in self._rate_history:
                        del self._rate_history[stale]

    def get_avg_rates(self, interface: str) -> Tuple[float, float]:
        with self._lock:
            if interface not in self._rate_history or not self._rate_history[interface]:
                return 0.0, 0.0
            
            rx_rates = [rate[0] for rate in self._rate_history[interface]]
            tx_rates = [rate[1] for rate in self._rate_history[interface]]
            
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
        with open(PROC_NET_DEV, 'r') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                if line.strip() and not line.startswith('Inter-face'):
                    lines.append(line.strip())
    except (OSError, IOError):
        pass
    return lines


@with_retry(max_attempts=3)
def parse_proc_net_dev(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> Dict[str, InterfaceTraffic]:
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
        except (ValueError, IndexError) as e:
            continue
        
        if not monitor.config.show_inactive and rx_bytes == 0 and tx_bytes == 0:
            continue
            
        state = monitor.get_interface_state(iface)
        addrs = monitor.get_interface_addrs(iface)
        mtu = monitor.get_mtu_cached(iface)
        speed = monitor.get_interface_speed(iface)
        duplex = monitor.get_interface_duplex(iface)
        
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
        state = monitor.get_interface_state(iface)
        state_color = Colors.GREEN if state == "up" else Colors.RED
        mtu = monitor.get_mtu_cached(iface)
        addrs = monitor.get_interface_addrs(iface)
        speed = monitor.get_interface_speed(iface)
        duplex = monitor.get_interface_duplex(iface)
        
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
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def watch_mode_improved(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]], interval: float) -> None:
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
            
            curr_stats = parse_proc_net_dev(monitor, filter_ifaces)
            
            for iface, now in curr_stats.items():
                if iface in prev_stats:
                    old = prev_stats[iface]
                    rx_rate = monitor.calculate_rate(now.rx_bytes, old.rx_bytes, interval)
                    tx_rate = monitor.calculate_rate(now.tx_bytes, old.tx_bytes, interval)
                    monitor.update_rate_history(iface, rx_rate, tx_rate)
            
            sorted_stats = sorted(curr_stats.items(), 
                                key=lambda x: monitor.get_avg_rates(x[0])[0] if x[0] in prev_stats else 0, 
                                reverse=True)
            
            for iface, now in sorted_stats:
                state_color = Colors.GREEN if now.is_up else Colors.RED
                speed_info = f" ({now.speed} Mbps)" if now.speed else ""
                
                line_parts = [f"{Colors.SEPIA}{iface:<12}{Colors.RESET} [{state_color}{now.state}{Colors.RESET}]{speed_info}"]
                
                if iface in prev_stats:
                    rx_rate = monitor.calculate_rate(now.rx_bytes, prev_stats[iface].rx_bytes, interval)
                    tx_rate = monitor.calculate_rate(now.tx_bytes, prev_stats[iface].tx_bytes, interval)
                    avg_rx, avg_tx = monitor.get_avg_rates(iface)
                    
                    line_parts.extend([
                        f"RX {Colors.GREEN}{monitor.format_rate_precise(rx_rate):<12}{Colors.RESET}",
                        f"TX {Colors.YELLOW}{monitor.format_rate_precise(tx_rate):<12}{Colors.RESET}",
                        f"Avg: {Colors.CYAN}RX{monitor.format_rate_precise(avg_rx)} TX{monitor.format_rate_precise(avg_tx)}{Colors.RESET}"
                    ])
                else:
                    line_parts.extend([
                        f"RX {Colors.GREEN}{monitor.format_bytes(now.rx_bytes):<12}{Colors.RESET}",
                        f"TX {Colors.YELLOW}{monitor.format_bytes(now.tx_bytes):<12}{Colors.RESET}",
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
            
            sleep_remaining = interval
            while sleep_remaining > 0 and not signal_handler.shutdown_requested:
                time.sleep(min(0.1, sleep_remaining))
                sleep_remaining -= 0.1
            
    except KeyboardInterrupt:
        pass
    finally:
        signal_handler.restore_handlers()
        print(f"\n{Colors.RED}Monitoring stopped after {update_count} updates.{Colors.RESET}")


def output_json(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    try:
        stats = parse_proc_net_dev(monitor, filter_ifaces)
        payload = {}
        for iface, traffic in stats.items():
            payload[iface] = {
                "rx_bytes": traffic.rx_bytes,
                "tx_bytes": traffic.tx_bytes,
                "rx_packets": traffic.rx_packets,
                "tx_packets": traffic.tx_packets,
                "rx_errs": traffic.rx_errs,
                "tx_errs": traffic.tx_errs,
                "rx_drop": traffic.rx_drop,
                "tx_drop": traffic.tx_drop,
                "mtu": traffic.mtu,
                "state": traffic.state,
                "ipv4_addr": traffic.ipv4_addr,
                "ipv6_addrs": traffic.ipv6_addrs,
                "speed": traffic.speed,
                "duplex": traffic.duplex,
                "is_active": traffic.is_active,
                "is_up": traffic.is_up,
                "total_bytes": traffic.total_bytes,
                "total_packets": traffic.total_packets,
            }
        
        json_str = json.dumps(payload, indent=2)
        print(json_str)
        
    except (TypeError, ValueError, OverflowError) as e:
        print(f'{{"error": "Failed to generate JSON: {str(e)}"}}', file=sys.stderr)
        sys.exit(1)


@contextlib.contextmanager
def resource_cleanup():
    try:
        yield
    finally:
        pass


def main() -> None:
    config = MonitorConfig()
    
    parser = argparse.ArgumentParser(
        description="Enhanced Network Monitor",
        epilog="""Examples:
  %(prog)s --watch
  %(prog)s --json > out.json
  %(prog)s -i eth0 wlan0 --watch
  %(prog)s --units decimal --show-inactive
  %(prog)s --hide-loopback --interval 2""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-i", "--interfaces", nargs="*", help="Limit output to given interfaces")
    parser.add_argument("-w", "--watch", nargs="?", const=1.0, type=float,
                       help="Watch mode with optional refresh interval (default 1s)")
    parser.add_argument("--json", action="store_true", help="Produce JSON output")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--show-inactive", action="store_true", help="Show inactive interfaces")
    parser.add_argument("--hide-loopback", action="store_true", help="Hide loopback interface")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--cache-ttl", type=float, default=5.0, help="Cache TTL in seconds")
    parser.add_argument("--max-interfaces", type=int, default=100, help="Maximum interfaces to display")
    parser.add_argument("--units", choices=["binary", "decimal"], default="binary", 
                       help="Display units (binary: KiB/MiB, decimal: KB/MB)")
    parser.add_argument("--sort-by", choices=["name", "rx", "tx", "total"], default="name",
                       help="Sort order for interfaces")
    
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"{Colors.RED}Error: This tool only works on Linux systems.{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
        
    if args.no_color:
        Colors.disable()

    config.interval = args.interval
    config.cache_ttl = args.cache_ttl
    config.max_interfaces = args.max_interfaces
    config.show_loopback = not args.hide_loopback
    config.show_inactive = args.show_inactive
    config.units = args.units

    config_errors = validate_config(config)
    if config_errors:
        for error in config_errors:
            print(f"{Colors.RED}Configuration error: {error}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    with NetworkMonitor(config) as monitor:
        try:
            if args.json:
                output_json(monitor, args.interfaces)
            elif args.watch is not None:
                watch_mode_improved(monitor, args.interfaces, args.watch)
            else:
                display_network_info(monitor, args.interfaces)
                display_traffic_stats(monitor, args.interfaces)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Interrupted.{Colors.RESET}")
            sys.exit(130)
        except Exception as e:
            print(f"{Colors.RED}Critical error: {e}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
