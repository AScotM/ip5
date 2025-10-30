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
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

PROC_NET_DEV = "/proc/net/dev"
SYSFS_NET_PATH = "/sys/class/net"
BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"]


@dataclass
class MonitorConfig:
    interval: float = 1.0
    cache_ttl: float = 5.0
    max_interfaces: int = 100
    show_loopback: bool = True
    show_inactive: bool = False
    precision: int = 1
    counter_bits: int = 64  # Assume 64-bit counters


class Colors:
    RESET = "\033[0m"
    GREY = "\033[38;5;250m"
    SEPIA = "\033[38;5;130m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"

    @classmethod
    def disable(cls) -> None:
        cls.RESET = cls.GREY = cls.SEPIA = cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""


class SignalHandler:
    def __init__(self):
        self.shutdown_requested = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum: int, frame) -> None:
        self.shutdown_requested = True


class NetworkMonitor:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self._ipv6_cache: Optional[Dict[str, List[str]]] = None
        self._ipv6_cache_time: float = 0
        self._mtu_cache: Dict[str, Optional[int]] = {}
        self._interface_cache: Optional[List[str]] = None
        self._interface_cache_time: float = 0

    def format_bytes(self, size: int) -> str:
        unit_idx = 0
        readable = float(size)
        while readable >= 1024 and unit_idx < len(BYTE_UNITS) - 1:
            readable /= 1024
            unit_idx += 1
        
        if unit_idx == 0:  # Bytes
            return f"{readable:.0f}{BYTE_UNITS[unit_idx]}"
        elif readable < 10:  # Small numbers
            return f"{readable:.2f}{BYTE_UNITS[unit_idx]}"
        else:
            return f"{readable:.1f}{BYTE_UNITS[unit_idx]}"

    def format_rate_precise(self, bytes_per_sec: float) -> str:
        if bytes_per_sec < 0:
            return "0B/s"
        
        unit_idx = 0
        readable = float(bytes_per_sec)
        while readable >= 1024 and unit_idx < len(BYTE_UNITS) - 1:
            readable /= 1024
            unit_idx += 1
        
        if unit_idx == 0:  # Bytes
            return f"{readable:.0f}{BYTE_UNITS[unit_idx]}/s"
        elif readable < 10:  # Small numbers
            return f"{readable:.2f}{BYTE_UNITS[unit_idx]}/s"
        else:
            return f"{readable:.1f}{BYTE_UNITS[unit_idx]}/s"

    def safe_interface_name(self, name: str) -> bool:
        return all(c.isalnum() or c in ("-", "_", ".") for c in name)

    def get_available_interfaces(self) -> List[str]:
        """Get list of valid network interfaces with caching."""
        now = time.time()
        if (self._interface_cache is not None and 
            (now - self._interface_cache_time) < self.config.cache_ttl):
            return self._interface_cache
        
        try:
            interfaces = []
            for iface in os.listdir(SYSFS_NET_PATH):
                iface_path = os.path.join(SYSFS_NET_PATH, iface)
                if (os.path.isdir(iface_path) and 
                    self.safe_interface_name(iface) and
                    (self.config.show_loopback or iface != "lo")):
                    interfaces.append(iface)
            
            self._interface_cache = sorted(interfaces)
            self._interface_cache_time = now
            return self._interface_cache
        except OSError:
            return []

    def validate_interfaces(self, requested_ifaces: Optional[List[str]]) -> List[str]:
        """Validate and filter requested interfaces."""
        available = self.get_available_interfaces()
        if not requested_ifaces:
            return available
        
        valid_ifaces = [iface for iface in requested_ifaces if iface in available]
        invalid_ifaces = set(requested_ifaces) - set(valid_ifaces)
        
        if invalid_ifaces:
            print(f"{Colors.RED}Warning: Invalid interfaces: {sorted(invalid_ifaces)}{Colors.RESET}")
        
        return valid_ifaces

    def _get_mtu_uncached(self, interface: str) -> Optional[int]:
        try:
            with open(f"{SYSFS_NET_PATH}/{interface}/mtu") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifr = struct.pack("16sI", interface.encode("utf-8")[:15], 0)
                mtu_data = fcntl.ioctl(s.fileno(), 0x8921, ifr)
                return struct.unpack("16sI", mtu_data)[1]
        except (OSError, struct.error):
            return None

    def get_mtu_cached(self, interface: str) -> Optional[int]:
        if interface in self._mtu_cache:
            return self._mtu_cache[interface]
        
        mtu = self._get_mtu_uncached(interface)
        self._mtu_cache[interface] = mtu
        return mtu

    def get_ipv4_info(self, interface: str) -> Optional[str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifr = struct.pack("16sH14s", interface.encode("utf-8")[:15], socket.AF_INET, b"\x00" * 14)
                addr_data = fcntl.ioctl(s.fileno(), 0x8915, ifr)
                ipv4 = socket.inet_ntoa(addr_data[20:24])
                mask_data = fcntl.ioctl(s.fileno(), 0x891b, ifr)
                netmask = socket.inet_ntoa(mask_data[20:24])
                prefix = bin(struct.unpack("!I", socket.inet_aton(netmask))[0]).count("1")
                return f"IPv4: {ipv4}/{prefix}"
        except OSError:
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
                    continue
                if iface and "inet6" in line and "scope global" in line:
                    parts = line.split()
                    addr, prefix = parts[1].split("/")
                    ipv6_map.setdefault(iface, []).append(f"IPv6: {addr}/{prefix}")

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ipv6_map

    def get_all_ipv6_info_cached(self) -> Dict[str, List[str]]:
        now = time.time()
        if (self._ipv6_cache is not None and 
            (now - self._ipv6_cache_time) < self.config.cache_ttl):
            return self._ipv6_cache
        
        self._ipv6_cache = self._get_all_ipv6_info_uncached()
        self._ipv6_cache_time = now
        return self._ipv6_cache

    def get_addrs(self, interface: str) -> str:
        addrs: List[str] = []
        ipv4 = self.get_ipv4_info(interface)
        if ipv4:
            addrs.append(ipv4)
        
        ipv6_map = self.get_all_ipv6_info_cached()
        if self.safe_interface_name(interface) and interface in ipv6_map:
            addrs.extend(ipv6_map[interface])
        
        return "; ".join(addrs) if addrs else "N/A"

    def calculate_rate(self, current: int, previous: int, interval: float) -> float:
        """Calculate rate with counter overflow protection."""
        if current >= previous:
            return (current - previous) / interval
        else:
            # Handle counter wrap-around
            max_count = 2**self.config.counter_bits - 1
            return ((max_count - previous) + current + 1) / interval


class InterfaceTraffic:
    def __init__(self, name: str) -> None:
        self.name = name
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_packets = 0
        self.tx_packets = 0
        self.rx_errs = 0
        self.tx_errs = 0
        self.mtu: Optional[int] = None

    def update(self, rx_bytes: int, tx_bytes: int, rx_pkts: int, tx_pkts: int,
               rx_errs: int, tx_errs: int, mtu: Optional[int]) -> None:
        self.rx_bytes, self.tx_bytes = rx_bytes, tx_bytes
        self.rx_packets, self.tx_packets = rx_pkts, tx_pkts
        self.rx_errs, self.tx_errs = rx_errs, tx_errs
        self.mtu = mtu

    @property
    def rx_human(self) -> str:
        return format_bytes(self.rx_bytes)

    @property
    def tx_human(self) -> str:
        return format_bytes(self.tx_bytes)


def format_bytes(size: int) -> str:
    unit_idx = 0
    readable = float(size)
    while readable >= 1024 and unit_idx < len(BYTE_UNITS) - 1:
        readable /= 1024
        unit_idx += 1
    return f"{readable:.1f}{BYTE_UNITS[unit_idx]}"


def format_rate(bytes_per_sec: int) -> str:
    return f"{format_bytes(bytes_per_sec)}/s"


def parse_traffic_stats(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> Dict[str, InterfaceTraffic]:
    stats: Dict[str, InterfaceTraffic] = {}
    if not os.path.exists(PROC_NET_DEV):
        return stats

    try:
        with open(PROC_NET_DEV) as f:
            lines = [ln.strip() for ln in f.readlines()[2:] if ln.strip()]
    except OSError as exc:
        print(f"{Colors.RED}Failed to read {PROC_NET_DEV}: {exc}{Colors.RESET}")
        return stats

    valid_ifaces = monitor.validate_interfaces(filter_ifaces)
    
    for line in lines:
        parts = line.split()
        if len(parts) < 12:
            continue
        iface = parts[0].rstrip(":")
        if valid_ifaces and iface not in valid_ifaces:
            continue
        try:
            rx_bytes, rx_pkts, rx_errs = int(parts[1]), int(parts[2]), int(parts[3])
            tx_bytes, tx_pkts, tx_errs = int(parts[9]), int(parts[10]), int(parts[11])
        except ValueError:
            continue
        
        # Skip inactive interfaces if configured
        if (not monitor.config.show_inactive and 
            rx_bytes == 0 and tx_bytes == 0 and 
            rx_pkts == 0 and tx_pkts == 0):
            continue
            
        tr = InterfaceTraffic(iface)
        tr.update(rx_bytes, tx_bytes, rx_pkts, tx_pkts, rx_errs, tx_errs, 
                 monitor.get_mtu_cached(iface))
        stats[iface] = tr
        
        # Limit number of interfaces
        if len(stats) >= monitor.config.max_interfaces:
            break
            
    return stats


def display_network_info(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    print(f"{Colors.BLUE}Network Interfaces:{Colors.RESET}")
    valid_ifaces = monitor.validate_interfaces(filter_ifaces)
    
    for iface in valid_ifaces:
        print(f"{Colors.SEPIA}{iface}:{Colors.RESET}")
        mtu = monitor.get_mtu_cached(iface)
        if mtu:
            print(f"    MTU: {mtu}")
        print(f"    Addresses: {monitor.get_addrs(iface)}")


def display_traffic_stats(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_traffic_stats(monitor, filter_ifaces)
    if not stats:
        print(f"{Colors.GREY}No traffic statistics available.{Colors.RESET}")
        return
        
    print(f"{Colors.BLUE}\nTraffic Statistics:{Colors.RESET}")
    for iface, tr in sorted(stats.items()):
        print(f"{Colors.SEPIA}{iface:<12}:{Colors.RESET}")
        print(f"    RX: {Colors.GREEN}{tr.rx_human} {Colors.GREY}({tr.rx_packets} pkts, {tr.rx_errs} errs){Colors.RESET}")
        print(f"    TX: {Colors.YELLOW}{tr.tx_human} {Colors.GREY}({tr.tx_packets} pkts, {tr.tx_errs} errs){Colors.RESET}")


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
            
            print(f"{Colors.BLUE}Live Traffic - Interval: {interval}s - Uptime: {elapsed_total:.0f}s - Updates: {update_count}{Colors.RESET}\n")
            
            curr_stats = parse_traffic_stats(monitor, filter_ifaces)
            
            for iface, now in sorted(curr_stats.items()):
                line_parts = [f"{Colors.SEPIA}{iface:<12}:{Colors.RESET}"]
                
                if iface in prev_stats:
                    old = prev_stats[iface]
                    rx_rate = monitor.calculate_rate(now.rx_bytes, old.rx_bytes, interval)
                    tx_rate = monitor.calculate_rate(now.tx_bytes, old.tx_bytes, interval)
                    
                    line_parts.extend([
                        f"RX {Colors.GREEN}{monitor.format_rate_precise(rx_rate):<12}{Colors.RESET}",
                        f"TX {Colors.YELLOW}{monitor.format_rate_precise(tx_rate):<12}{Colors.RESET}",
                        f"Total: RX{monitor.format_bytes(now.rx_bytes)} TX{monitor.format_bytes(now.tx_bytes)}"
                    ])
                else:
                    line_parts.extend([
                        f"RX {Colors.GREEN}{now.rx_human:<12}{Colors.RESET}",
                        f"TX {Colors.YELLOW}{now.tx_human:<12}{Colors.RESET}",
                        f"{Colors.GREY}(initial){Colors.RESET}"
                    ])
                
                print(" ".join(line_parts))
            
            if not curr_stats:
                print(f"{Colors.GREY}No interfaces to monitor.{Colors.RESET}")
            
            print(f"\n{Colors.GREY}[Ctrl+C to stop] | Interfaces: {len(curr_stats)} | {time.strftime('%H:%M:%S')}{Colors.RESET}")
            
            prev_stats = curr_stats
            update_count += 1
            
            # Sleep with shutdown check
            sleep_remaining = interval
            while sleep_remaining > 0 and not signal_handler.shutdown_requested:
                time.sleep(min(0.1, sleep_remaining))
                sleep_remaining -= 0.1
            
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{Colors.RED}Monitoring stopped after {update_count} updates.{Colors.RESET}")


def output_json(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_traffic_stats(monitor, filter_ifaces)
    payload = {
        iface: {
            "rx_bytes": tr.rx_bytes,
            "tx_bytes": tr.tx_bytes,
            "rx_packets": tr.rx_packets,
            "tx_packets": tr.tx_packets,
            "rx_errs": tr.rx_errs,
            "tx_errs": tr.tx_errs,
            "mtu": tr.mtu,
            "addrs": monitor.get_addrs(iface),
        }
        for iface, tr in stats.items()
    }
    print(json.dumps(payload, indent=2))


@contextlib.contextmanager
def resource_cleanup():
    """Context manager for resource cleanup."""
    try:
        yield
    finally:
        # Cleanup code if needed
        pass


def main() -> None:
    config = MonitorConfig()
    
    p = argparse.ArgumentParser(
        description="Enhanced Network Monitor",
        epilog="Examples: %(prog)s --watch | %(prog)s --json > out.json",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-i", "--interfaces", nargs="*", help="Limit output to given interfaces")
    p.add_argument("-w", "--watch", nargs="?", const=1.0, type=float,
                   help="Watch mode with optional refresh interval (default 1s)")
    p.add_argument("--json", action="store_true", help="Produce JSON output")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--show-inactive", action="store_true", help="Show inactive interfaces")
    p.add_argument("--hide-loopback", action="store_true", help="Hide loopback interface")
    p.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    p.add_argument("--cache-ttl", type=float, default=5.0, help="Cache TTL in seconds")
    
    a = p.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"{Colors.RED}Error: Linux only.{Colors.RESET}")
        sys.exit(1)
        
    if a.no_color:
        Colors.disable()

    # Update config from arguments
    config.interval = a.interval
    config.cache_ttl = a.cache_ttl
    config.show_loopback = not a.hide_loopback
    config.show_inactive = a.show_inactive

    monitor = NetworkMonitor(config)

    with resource_cleanup():
        try:
            if a.json:
                output_json(monitor, a.interfaces)
            elif a.watch is not None:
                watch_mode_improved(monitor, a.interfaces, a.watch)
            else:
                display_network_info(monitor, a.interfaces)
                display_traffic_stats(monitor, a.interfaces)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Interrupted.{Colors.RESET}")
            sys.exit(130)
        except Exception as e:
            print(f"{Colors.RED}Critical error: {e}{Colors.RESET}")
            sys.exit(1)


if __name__ == "__main__":
    main()
