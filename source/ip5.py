#!/usr/bin/env python3

import argparse
import json
import os
import sys
import time
import struct
import fcntl
import socket
import subprocess
from typing import Optional, List, Dict

FILTER_INTERFACES = None
COLOR_OUTPUT = True
BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"]
PROC_NET_DEV = "/proc/net/dev"
SYSFS_NET_PATH = "/sys/class/net"

class Colors:
    RESET = "\033[0m"
    GREY = "\033[38;5;250m"
    SEPIA = "\033[38;5;130m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    
    @classmethod
    def disable(cls):
        cls.RESET = cls.GREY = cls.SEPIA = cls.RED = cls.GREEN = ""

class InterfaceTraffic:
    def __init__(self, name: str):
        self.name = name
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_packets = 0
        self.tx_packets = 0
        self.rx_errs = 0
        self.tx_errs = 0
        self.mtu = 0
        
    def update(self, rx_bytes: int, tx_bytes: int, rx_pkts: int, tx_pkts: int, rx_errs: int, tx_errs: int, mtu: Optional[int]):
        self.rx_bytes = rx_bytes
        self.tx_bytes = tx_bytes
        self.rx_packets = rx_pkts
        self.tx_packets = tx_pkts
        self.rx_errs = rx_errs
        self.tx_errs = tx_errs
        if mtu:
            self.mtu = mtu
        
    @property
    def rx_human(self) -> str:
        return format_bytes(self.rx_bytes)
    
    @property 
    def tx_human(self) -> str:
        return format_bytes(self.tx_bytes)

def format_bytes(size: int) -> str:
    unit_index = 0
    readable_size = float(size)
    while readable_size >= 1024 and unit_index < len(BYTE_UNITS) - 1:
        readable_size /= 1024
        unit_index += 1
    return f"{readable_size:.1f} {BYTE_UNITS[unit_index]}"

def format_rate(bytes_per_sec: int) -> str:
    return format_bytes(bytes_per_sec) + "/s"

def get_mtu(interface: str) -> Optional[int]:
    try:
        with open(f"{SYSFS_NET_PATH}/{interface}/mtu") as f:
            return int(f.read().strip())
    except (IOError, ValueError):
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            ifr = struct.pack('16sH', interface.encode(), 0)
            mtu_data = fcntl.ioctl(s.fileno(), 0x8921, ifr)
            return struct.unpack('16sH', mtu_data[:18])[1]
    except (OSError, struct.error):
        pass
    return None

def get_addrs(interface: str) -> str:
    addrs = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifr = struct.pack('16sH', interface.encode(), socket.AF_INET)
        addr_data = fcntl.ioctl(s.fileno(), 0x8915, ifr)
        ipv4 = socket.inet_ntoa(addr_data[20:24])
        mask_data = fcntl.ioctl(s.fileno(), 0x891b, ifr)
        netmask = socket.inet_ntoa(mask_data[20:24])
        addrs.append(f"IPv4: {ipv4}/{netmask}")
    except OSError:
        pass
    try:
        ipv6_out = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', interface], capture_output=True, text=True, timeout=5)
        if ipv6_out.returncode == 0 and 'inet6' in ipv6_out.stdout:
            lines = ipv6_out.stdout.split('\n')
            for line in lines:
                if 'inet6' in line and 'scope global' in line:
                    ipv6_addr = line.split('inet6 ')[1].split('/')[0].strip()
                    prefix = line.split('inet6 ')[1].split('/')[1].split(' ')[0]
                    addrs.append(f"IPv6: {ipv6_addr}/{prefix}")
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "; ".join(addrs) or "N/A"

def get_interface_info(interface: str):
    print(f"{Colors.SEPIA}{interface}:{Colors.RESET}")
    mtu = get_mtu(interface)
    if mtu:
        print(f"    MTU: {mtu}")
    addrs = get_addrs(interface)
    print(f"    Addresses: {addrs}")

def display_network_info(interfaces: Optional[List[str]] = None):
    print(f"{Colors.GREY}Network Interfaces:{Colors.RESET}")
    all_ifaces = interfaces or [i for i in os.listdir(SYSFS_NET_PATH) if os.path.isdir(f"{SYSFS_NET_PATH}/{i}")]
    for interface in sorted(all_ifaces):
        if FILTER_INTERFACES and interface not in FILTER_INTERFACES:
            continue
        get_interface_info(interface)

def parse_traffic_stats(interfaces: Optional[List[str]] = None) -> Dict[str, InterfaceTraffic]:
    stats_dict = {}
    if not os.path.exists(PROC_NET_DEV):
        return stats_dict
    try:
        with open(PROC_NET_DEV) as f:
            lines = [l.strip() for l in f.readlines()[2:] if l.strip()]
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            iface = parts[0].rstrip(':')
            if interfaces and iface not in interfaces:
                continue
            try:
                rx_bytes, rx_pkts, rx_errs = int(parts[1]), int(parts[2]), int(parts[3])
                tx_bytes, tx_pkts, tx_errs = int(parts[9]), int(parts[10]), int(parts[11])
                traffic = InterfaceTraffic(iface)
                traffic.update(rx_bytes, tx_bytes, rx_pkts, tx_pkts, rx_errs, tx_errs, get_mtu(iface))
                stats_dict[iface] = traffic
            except ValueError:
                continue
    except Exception as e:
        print(f"{Colors.RED}Error reading stats: {e}{Colors.RESET}")
    return stats_dict

def display_traffic_stats(interfaces: Optional[List[str]] = None):
    stats_dict = parse_traffic_stats(interfaces)
    if not stats_dict:
        return
    print(f"{Colors.GREY}\nTraffic Statistics:{Colors.RESET}")
    for iface, traffic in sorted(stats_dict.items()):
        print(f"{Colors.SEPIA}  {iface}:{Colors.RESET}")
        print(f"    RX: {Colors.GREY}{traffic.rx_human} ({traffic.rx_packets} pkts, {traffic.rx_errs} errs){Colors.RESET}")
        print(f"    TX: {Colors.GREY}{traffic.tx_human} ({traffic.tx_packets} pkts, {traffic.tx_errs} errs){Colors.RESET}")

def watch_mode(interfaces: Optional[List[str]], interval: float):
    prev_stats = {}
    try:
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            print(f"{Colors.GREY}Live Traffic (Refresh: {interval}s){Colors.RESET}\n")
            current_stats = parse_traffic_stats(interfaces)
            for iface, traffic in sorted(current_stats.items()):
                if iface in prev_stats:
                    prev = prev_stats[iface]
                    rx_rate = (traffic.rx_bytes - prev.rx_bytes) / interval
                    tx_rate = (traffic.tx_bytes - prev.tx_bytes) / interval
                    print(f"{Colors.SEPIA}  {iface}:{Colors.RESET}")
                    print(f"    RX: {Colors.GREY}{format_rate(int(rx_rate))} ({traffic.rx_packets} pkts){Colors.RESET}")
                    print(f"    TX: {Colors.GREY}{format_rate(int(tx_rate))} ({traffic.tx_packets} pkts){Colors.RESET}")
                else:
                    display_traffic_stats([iface])
            prev_stats = current_stats
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Stopped.{Colors.RESET}")

def output_json(interfaces: Optional[List[str]] = None):
    stats_dict = parse_traffic_stats(interfaces)
    data = {}
    for iface, traffic in stats_dict.items():
        data[iface] = {
            "rx_bytes": traffic.rx_bytes,
            "tx_bytes": traffic.tx_bytes,
            "rx_packets": traffic.rx_packets,
            "tx_packets": traffic.tx_packets,
            "rx_errs": traffic.rx_errs,
            "tx_errs": traffic.tx_errs,
            "mtu": traffic.mtu,
            "addrs": get_addrs(iface)
        }
    print(json.dumps(data, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Simple Network Monitor (Extended)")
    parser.add_argument("--interfaces", "-i", nargs="*", help="Filter interfaces (space-separated)")
    parser.add_argument("--watch", "-w", type=float, help="Watch mode interval (seconds)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    args = parser.parse_args()
    
    global FILTER_INTERFACES
    FILTER_INTERFACES = set(args.interfaces) if args.interfaces else None
    
    if not sys.platform.startswith("linux"):
        print(f"{Colors.RED}Error: Linux-only script{Colors.RESET}")
        sys.exit(1)
    
    if not COLOR_OUTPUT or args.no_color:
        Colors.disable()
    
    interfaces_list = list(FILTER_INTERFACES) if FILTER_INTERFACES else None
    
    try:
        if args.json:
            output_json(interfaces_list)
        elif args.watch:
            watch_mode(interfaces_list, args.watch)
        else:
            display_network_info(interfaces_list)
            display_traffic_stats(interfaces_list)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Interrupted{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Critical error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
