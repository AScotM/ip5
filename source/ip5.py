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
from dataclasses import dataclass, field
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
    counter_bits: int = 64
    units: str = "binary"


class Colors:
    RESET = "\033[0m"
    GREY = "\033[38;5;250m"
    SEPIA = "\033[38;5;130m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"

    @classmethod
    def disable(cls) -> None:
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, "")


class SignalHandler:
    def __init__(self):
        self.shutdown_requested = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum: int, frame) -> None:
        self.shutdown_requested = True


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

    @property
    def is_active(self) -> bool:
        return self.rx_bytes > 0 or self.tx_bytes > 0 or self.rx_packets > 0 or self.tx_packets > 0

    @property
    def is_up(self) -> bool:
        return self.state == "up"


class NetworkMonitor:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self._ipv6_cache: Optional[Dict[str, List[str]]] = None
        self._ipv6_cache_time: float = 0
        self._mtu_cache: Dict[str, Optional[int]] = {}
        self._state_cache: Dict[str, str] = {}
        self._interface_cache: Optional[List[str]] = None
        self._interface_cache_time: float = 0

    def get_divisor(self) -> int:
        return 1000 if self.config.units == "decimal" else 1024

    def format_bytes(self, size: int) -> str:
        divisor = self.get_divisor()
        unit_idx = 0
        readable = float(size)
        while readable >= divisor and unit_idx < len(BYTE_UNITS) - 1:
            readable /= divisor
            unit_idx += 1
        
        if unit_idx == 0:
            return f"{readable:.0f}{BYTE_UNITS[unit_idx]}"
        elif readable < 10:
            return f"{readable:.2f}{BYTE_UNITS[unit_idx]}"
        else:
            return f"{readable:.1f}{BYTE_UNITS[unit_idx]}"

    def format_rate_precise(self, bytes_per_sec: float) -> str:
        if bytes_per_sec < 0:
            return "0B/s"
        
        divisor = self.get_divisor()
        unit_idx = 0
        readable = float(bytes_per_sec)
        while readable >= divisor and unit_idx < len(BYTE_UNITS) - 1:
            readable /= divisor
            unit_idx += 1
        
        if unit_idx == 0:
            return f"{readable:.0f}{BYTE_UNITS[unit_idx]}/s"
        elif readable < 10:
            return f"{readable:.2f}{BYTE_UNITS[unit_idx]}/s"
        else:
            return f"{readable:.1f}{BYTE_UNITS[unit_idx]}/s"

    def safe_interface_name(self, name: str) -> bool:
        return all(c.isalnum() or c in ("-", "_", ".", ":") for c in name)

    def get_interface_state(self, interface: str) -> str:
        if interface in self._state_cache:
            return self._state_cache[interface]
        
        state_path = f"{SYSFS_NET_PATH}/{interface}/operstate"
        try:
            with open(state_path) as f:
                state = f.read().strip().lower()
                self._state_cache[interface] = state
                return state
        except (OSError, IOError):
            self._state_cache[interface] = "unknown"
            return "unknown"

    def get_available_interfaces(self) -> List[str]:
        now = time.time()
        if (self._interface_cache is not None and 
            (now - self._interface_cache_time) < self.config.cache_ttl):
            return self._interface_cache
        
        try:
            interfaces = []
            for iface in os.listdir(SYSFS_NET_PATH):
                iface_path = os.path.join(SYSFS_NET_PATH, iface)
                if (os.path.isdir(iface_path) and 
                    self.safe_interface_name(iface)):
                    
                    if not self.config.show_loopback:
                        if iface == "lo":
                            continue
                        carrier_path = f"{SYSFS_NET_PATH}/{iface}/carrier"
                        try:
                            with open(carrier_path) as f:
                                if f.read().strip() == "1":
                                    continue
                        except (OSError, IOError):
                            pass
                    
                    interfaces.append(iface)
            
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
                return f"{ipv4}/{prefix}"
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
                    ipv6_map.setdefault(iface, []).append(f"{addr}/{prefix}")

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
            parts.append(f"IPv6: {', '.join(addrs['ipv6'][:2])}")  # Limit IPv6 display
        return "; ".join(parts) if parts else "N/A"

    def calculate_rate(self, current: int, previous: int, interval: float) -> float:
        if current >= previous:
            return (current - previous) / interval
        else:
            max_count = 2**self.config.counter_bits - 1
            return ((max_count - previous) + current + 1) / interval


def parse_proc_net_dev(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> Dict[str, InterfaceTraffic]:
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
            
        state = monitor.get_interface_state(iface)
        addrs = monitor.get_interface_addrs(iface)
        mtu = monitor.get_mtu_cached(iface)
        
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
            ipv6_addrs=addrs["ipv6"]
        )
        
        stats[iface] = traffic
        
        if len(stats) >= monitor.config.max_interfaces:
            break
            
    return stats


def display_network_info(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    print(f"{Colors.BLUE}Network Interface Information:{Colors.RESET}")
    valid_ifaces = monitor.validate_interfaces(filter_ifaces)
    
    for iface in valid_ifaces:
        state = monitor.get_interface_state(iface)
        state_color = Colors.GREEN if state == "up" else Colors.RED
        mtu = monitor.get_mtu_cached(iface)
        addrs = monitor.get_interface_addrs(iface)
        
        print(f"\n{Colors.SEPIA}{iface}{Colors.RESET} [{state_color}{state}{Colors.RESET}]")
        if mtu:
            print(f"  MTU: {mtu}")
        print(f"  Addresses: {monitor.format_addrs_string(addrs)}")


def display_traffic_stats(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_proc_net_dev(monitor, filter_ifaces)
    if not stats:
        print(f"{Colors.GREY}No traffic statistics available.{Colors.RESET}")
        return
        
    print(f"{Colors.BLUE}\nTraffic Statistics:{Colors.RESET}")
    for iface, traffic in sorted(stats.items()):
        state_color = Colors.GREEN if traffic.is_up else Colors.RED
        print(f"\n{Colors.SEPIA}{iface:<12}{Colors.RESET} [{state_color}{traffic.state}{Colors.RESET}]")
        print(f"  RX: {Colors.GREEN}{monitor.format_bytes(traffic.rx_bytes):<10}{Colors.RESET} "
              f"{Colors.GREY}({traffic.rx_packets} pkts, {traffic.rx_errs} errs, {traffic.rx_drop} drop){Colors.RESET}")
        print(f"  TX: {Colors.YELLOW}{monitor.format_bytes(traffic.tx_bytes):<10}{Colors.RESET} "
              f"{Colors.GREY}({traffic.tx_packets} pkts, {traffic.tx_errs} errs, {traffic.tx_drop} drop){Colors.RESET}")


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
            
            for iface, now in sorted(curr_stats.items()):
                state_color = Colors.GREEN if now.is_up else Colors.RED
                line_parts = [f"{Colors.SEPIA}{iface:<12}{Colors.RESET} [{state_color}{now.state}{Colors.RESET}]"]
                
                if iface in prev_stats:
                    old = prev_stats[iface]
                    rx_rate = monitor.calculate_rate(now.rx_bytes, old.rx_bytes, interval)
                    tx_rate = monitor.calculate_rate(now.tx_bytes, old.tx_bytes, interval)
                    
                    line_parts.extend([
                        f"RX {Colors.GREEN}{monitor.format_rate_precise(rx_rate):<12}{Colors.RESET}",
                        f"TX {Colors.YELLOW}{monitor.format_rate_precise(tx_rate):<12}{Colors.RESET}",
                        f"Total: {Colors.CYAN}RX{monitor.format_bytes(now.rx_bytes)} TX{monitor.format_bytes(now.tx_bytes)}{Colors.RESET}"
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
            print(f"\n{Colors.GREY}[Ctrl+C to stop] | Interfaces: {len(curr_stats)} (active: {active_count}) | {time.strftime('%H:%M:%S')}{Colors.RESET}")
            
            prev_stats = curr_stats
            update_count += 1
            
            sleep_remaining = interval
            while sleep_remaining > 0 and not signal_handler.shutdown_requested:
                time.sleep(min(0.1, sleep_remaining))
                sleep_remaining -= 0.1
            
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{Colors.RED}Monitoring stopped after {update_count} updates.{Colors.RESET}")


def output_json(monitor: NetworkMonitor, filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_proc_net_dev(monitor, filter_ifaces)
    payload = {
        iface: {
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
            "is_active": traffic.is_active,
            "is_up": traffic.is_up,
        }
        for iface, traffic in stats.items()
    }
    print(json.dumps(payload, indent=2))


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
        epilog="Examples:\n  %(prog)s --watch\n  %(prog)s --json > out.json\n  %(prog)s -i eth0 wlan0 --watch",
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
    
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"{Colors.RED}Error: This tool only works on Linux systems.{Colors.RESET}")
        sys.exit(1)
        
    if args.no_color:
        Colors.disable()

    config.interval = args.interval
    config.cache_ttl = args.cache_ttl
    config.max_interfaces = args.max_interfaces
    config.show_loopback = not args.hide_loopback
    config.show_inactive = args.show_inactive
    config.units = args.units

    monitor = NetworkMonitor(config)

    with resource_cleanup():
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
            print(f"{Colors.RED}Critical error: {e}{Colors.RESET}")
            sys.exit(1)


if __name__ == "__main__":
    main()
