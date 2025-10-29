#!/usr/bin/env python3 -u

import argparse
import fcntl
import json
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Dict, List, Optional

PROC_NET_DEV = "/proc/net/dev"
SYSFS_NET_PATH = "/sys/class/net"
BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"]


class Colors:
    RESET = "\033[0m"
    GREY = "\033[38;5;250m"
    SEPIA = "\033[38;5;130m"
    RED = "\033[31m"
    GREEN = "\033[32m"

    @classmethod
    def disable(cls) -> None:
        cls.RESET = cls.GREY = cls.SEPIA = cls.RED = cls.GREEN = ""


def format_bytes(size: int) -> str:
    unit_idx = 0
    readable = float(size)
    while readable >= 1024 and unit_idx < len(BYTE_UNITS) - 1:
        readable /= 1024
        unit_idx += 1
    return f"{readable:.1f} {BYTE_UNITS[unit_idx]}"


def format_rate(bytes_per_sec: int) -> str:
    return f"{format_bytes(bytes_per_sec)}/s"


def safe_interface_name(name: str) -> bool:
    return all(c.isalnum() or c in ("-", "_") for c in name)


def get_mtu(interface: str) -> Optional[int]:
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


def get_ipv4_info(interface: str) -> Optional[str]:
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


def get_all_ipv6_info() -> Dict[str, List[str]]:
    """Fetch all IPv6 addresses once for performance."""
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


def get_addrs(interface: str, ipv6_map: Dict[str, List[str]]) -> str:
    addrs: List[str] = []
    ipv4 = get_ipv4_info(interface)
    if ipv4:
        addrs.append(ipv4)
    if safe_interface_name(interface) and interface in ipv6_map:
        addrs.extend(ipv6_map[interface])
    return "; ".join(addrs) or "N/A"


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


def parse_traffic_stats(filter_ifaces: Optional[List[str]] = None) -> Dict[str, InterfaceTraffic]:
    stats: Dict[str, InterfaceTraffic] = {}
    if not os.path.exists(PROC_NET_DEV):
        return stats

    try:
        with open(PROC_NET_DEV) as f:
            lines = [ln.strip() for ln in f.readlines()[2:] if ln.strip()]
    except OSError as exc:
        print(f"{Colors.RED}Failed to read {PROC_NET_DEV}: {exc}{Colors.RESET}")
        return stats

    for line in lines:
        parts = line.split()
        if len(parts) < 12:
            continue
        iface = parts[0].rstrip(":")
        if filter_ifaces and iface not in filter_ifaces:
            continue
        try:
            rx_bytes, rx_pkts, rx_errs = int(parts[1]), int(parts[2]), int(parts[3])
            tx_bytes, tx_pkts, tx_errs = int(parts[9]), int(parts[10]), int(parts[11])
        except ValueError:
            continue
        tr = InterfaceTraffic(iface)
        tr.update(rx_bytes, tx_bytes, rx_pkts, tx_pkts, rx_errs, tx_errs, get_mtu(iface))
        stats[iface] = tr
    return stats


def display_network_info(filter_ifaces: Optional[List[str]] = None) -> None:
    print(f"{Colors.GREY}Network Interfaces:{Colors.RESET}")
    ipv6_map = get_all_ipv6_info()
    all_ifaces = filter_ifaces or [i for i in os.listdir(SYSFS_NET_PATH)
                                   if os.path.isdir(f"{SYSFS_NET_PATH}/{i}")]
    for iface in sorted(all_ifaces):
        print(f"{Colors.SEPIA}{iface}:{Colors.RESET}")
        mtu = get_mtu(iface)
        if mtu:
            print(f"    MTU: {mtu}")
        print(f"    Addresses: {get_addrs(iface, ipv6_map)}")


def display_traffic_stats(filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_traffic_stats(filter_ifaces)
    if not stats:
        return
    print(f"{Colors.GREY}\nTraffic Statistics:{Colors.RESET}")
    for iface, tr in sorted(stats.items()):
        print(f"{Colors.SEPIA}{iface:<12}:{Colors.RESET}")
        print(f"    RX: {Colors.GREY}{tr.rx_human} ({tr.rx_packets} pkts, {tr.rx_errs} errs){Colors.RESET}")
        print(f"    TX: {Colors.GREY}{tr.tx_human} ({tr.tx_packets} pkts, {tr.tx_errs} errs){Colors.RESET}")


def clear_screen() -> None:
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def watch_mode(filter_ifaces: Optional[List[str]], interval: float) -> None:
    prev: Dict[str, InterfaceTraffic] = {}
    try:
        while True:
            clear_screen()
            print(f"{Colors.GREY}Live Traffic (refresh: {interval}s){Colors.RESET}\n")
            curr = parse_traffic_stats(filter_ifaces)
            for iface, now in sorted(curr.items()):
                if iface in prev:
                    old = prev[iface]
                    rx_rate = max(0, now.rx_bytes - old.rx_bytes) / interval
                    tx_rate = max(0, now.tx_bytes - old.tx_bytes) / interval
                    print(f"{Colors.SEPIA}{iface:<12}:{Colors.RESET} "
                          f"RX {Colors.GREY}{format_rate(int(rx_rate))}{Colors.RESET} "
                          f"TX {Colors.GREY}{format_rate(int(tx_rate))}{Colors.RESET}")
                else:
                    print(f"{Colors.SEPIA}{iface:<12}:{Colors.RESET}")
                    print(f"    RX {Colors.GREY}{now.rx_human}{Colors.RESET} ({now.rx_packets} pkts)")
                    print(f"    TX {Colors.GREY}{now.tx_human}{Colors.RESET} ({now.tx_packets} pkts)")
            prev = curr
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Stopped.{Colors.RESET}")


def output_json(filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_traffic_stats(filter_ifaces)
    ipv6_map = get_all_ipv6_info()
    payload = {
        iface: {
            "rx_bytes": tr.rx_bytes,
            "tx_bytes": tr.tx_bytes,
            "rx_packets": tr.rx_packets,
            "tx_packets": tr.tx_packets,
            "rx_errs": tr.rx_errs,
            "tx_errs": tr.tx_errs,
            "mtu": tr.mtu,
            "addrs": get_addrs(iface, ipv6_map),
        }
        for iface, tr in stats.items()
    }
    print(json.dumps(payload, indent=2))


def main() -> None:
    p = argparse.ArgumentParser(
        description="Simple Network Monitor (Extended)",
        epilog="Examples: %(prog)s --watch | %(prog)s --json > out.json",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-i", "--interfaces", nargs="*", help="Limit output to given interfaces")
    p.add_argument("-w", "--watch", nargs="?", const=1.0, type=float,
                   help="Watch mode with optional refresh interval (default 1s)")
    p.add_argument("--json", action="store_true", help="Produce JSON output")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    a = p.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"{Colors.RED}Linux only.{Colors.RESET}")
        sys.exit(1)
    if a.no_color:
        Colors.disable()

    try:
        if a.json:
            output_json(a.interfaces)
        elif a.watch is not None:
            watch_mode(a.interfaces, a.watch)
        else:
            display_network_info(a.interfaces)
            display_traffic_stats(a.interfaces)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Interrupted.{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Critical error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
