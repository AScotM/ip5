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
    GREY  = "\033[38;5;250m"
    SEPIA = "\033[38;5;130m"
    RED   = "\033[31m"
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

def get_addrs(interface: str) -> str:
    addrs: List[str] = []

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifr = struct.pack("16sH14s", interface.encode("utf-8")[:15], socket.AF_INET, b"\x00" * 14)
        addr_data = fcntl.ioctl(s.fileno(), 0x8915, ifr)
        ipv4 = socket.inet_ntoa(addr_data[20:24])

        mask_data = fcntl.ioctl(s.fileno(), 0x891b, ifr)
        netmask = socket.inet_ntoa(mask_data[20:24])

        netmask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        prefix = bin(netmask_int).count("1")
        addrs.append(f"IPv4: {ipv4}/{prefix}")
    except OSError:
        pass
    finally:
        s.close()

    if safe_interface_name(interface):
        try:
            proc = subprocess.run(
                ["ip", "-6", "addr", "show", "dev", interface],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and "inet6" in proc.stdout:
                for line in proc.stdout.splitlines():
                    if "inet6" in line and "scope global" in line:
                        parts = line.strip().split()
                        ipv6_addr, prefix = parts[1].split("/")
                        addrs.append(f"IPv6: {ipv6_addr}/{prefix}")
                        break
        except FileNotFoundError:
            addrs.append("IPv6: ip command not found")
        except subprocess.TimeoutExpired:
            addrs.append("IPv6: lookup timed out")
    else:
        addrs.append("IPv6: invalid interface name")

    return "; ".join(addrs) or "N/A"

def get_interface_info(interface: str) -> None:
    print(f"{Colors.SEPIA}{interface}:{Colors.RESET}")

    mtu = get_mtu(interface)
    if mtu:
        print(f"    MTU: {mtu}")

    addrs = get_addrs(interface)
    print(f"    Addresses: {addrs}")

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

    def update(
        self,
        rx_bytes: int,
        tx_bytes: int,
        rx_pkts: int,
        tx_pkts: int,
        rx_errs: int,
        tx_errs: int,
        mtu: Optional[int],
    ) -> None:
        self.rx_bytes = rx_bytes
        self.tx_bytes = tx_bytes
        self.rx_packets = rx_pkts
        self.tx_packets = tx_pkts
        self.rx_errs = rx_errs
        self.tx_errs = tx_errs
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

        traffic = InterfaceTraffic(iface)
        traffic.update(
            rx_bytes,
            tx_bytes,
            rx_pkts,
            tx_pkts,
            rx_errs,
            tx_errs,
            get_mtu(iface),
        )
        stats[iface] = traffic

    return stats

def display_network_info(filter_ifaces: Optional[List[str]] = None) -> None:
    print(f"{Colors.GREY}Network Interfaces:{Colors.RESET}")

    all_ifaces = filter_ifaces or [
        i for i in os.listdir(SYSFS_NET_PATH) if os.path.isdir(f"{SYSFS_NET_PATH}/{i}")
    ]

    for iface in sorted(all_ifaces):
        get_interface_info(iface)

def display_traffic_stats(filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_traffic_stats(filter_ifaces)
    if not stats:
        return

    print(f"{Colors.GREY}\nTraffic Statistics:{Colors.RESET}")
    for iface, tr in sorted(stats.items()):
        print(f"{Colors.SEPIA}{iface:<12}:{Colors.RESET}")
        print(
            f"    RX: {Colors.GREY}{tr.rx_human} "
            f"({tr.rx_packets} pkts, {tr.rx_errs} errs){Colors.RESET}"
        )
        print(
            f"    TX: {Colors.GREY}{tr.tx_human} "
            f"({tr.tx_packets} pkts, {tr.tx_errs} errs){Colors.RESET}"
        )

def watch_mode(filter_ifaces: Optional[List[str]], interval: float) -> None:
    previous: Dict[str, InterfaceTraffic] = {}

    try:
        while True:
            os.system("clear" if os.name == "posix" else "cls")
            print(f"{Colors.GREY}Live Traffic (refresh: {interval}s){Colors.RESET}\n")

            current = parse_traffic_stats(filter_ifaces)

            for iface, cur in sorted(current.items()):
                if iface in previous:
                    prev = previous[iface]

                    delta_rx = max(0, cur.rx_bytes - prev.rx_bytes)
                    delta_tx = max(0, cur.tx_bytes - prev.tx_bytes)

                    rx_rate = delta_rx / interval
                    tx_rate = delta_tx / interval

                    print(
                        f"{Colors.SEPIA}{iface:<12}:{Colors.RESET} "
                        f"RX {Colors.GREY}{format_rate(int(rx_rate))}{Colors.RESET} "
                        f"TX {Colors.GREY}{format_rate(int(tx_rate))}{Colors.RESET}"
                    )
                else:
                    print(f"{Colors.SEPIA}{iface:<12}:{Colors.RESET}")
                    print(
                        f"    RX {Colors.GREY}{cur.rx_human}{Colors.RESET} "
                        f"({cur.rx_packets} pkts)"
                    )
                    print(
                        f"    TX {Colors.GREY}{cur.tx_human}{Colors.RESET} "
                        f"({cur.tx_packets} pkts)"
                    )

            previous = current
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Stopped.{Colors.RESET}")

def output_json(filter_ifaces: Optional[List[str]] = None) -> None:
    stats = parse_traffic_stats(filter_ifaces)
    payload: Dict[str, Dict] = {}

    for iface, tr in stats.items():
        payload[iface] = {
            "rx_bytes": tr.rx_bytes,
            "tx_bytes": tr.tx_bytes,
            "rx_packets": tr.rx_packets,
            "tx_packets": tr.tx_packets,
            "rx_errs": tr.rx_errs,
            "tx_errs": tr.tx_errs,
            "mtu": tr.mtu,
            "addrs": get_addrs(iface),
        }

    print(json.dumps(payload, indent=2))

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simple Network Monitor (Extended)",
        epilog="Examples: %(prog)s --watch 2 | %(prog)s --json > out.json",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--interfaces",
        "-i",
        nargs="*",
        metavar="IFACE",
        help="Limit output to the listed interfaces (space-separated)",
    )
    parser.add_argument(
        "--watch",
        "-w",
        type=float,
        metavar="SECONDS",
        help="Enable live-watch mode; refresh interval in seconds",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Produce JSON output instead of the human-readable tables",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Suppress ANSI colour codes (useful for logging or non-TTY output)",
    )
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"{Colors.RED}Error: This script runs on Linux only.{Colors.RESET}")
        sys.exit(1)

    if args.no_color:
        Colors.disable()

    iface_filter: Optional[List[str]] = args.interfaces if args.interfaces else None

    try:
        if args.json:
            output_json(iface_filter)
        elif args.watch:
            watch_mode(iface_filter, args.watch)
        else:
            display_network_info(iface_filter)
            display_traffic_stats(iface_filter)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Interrupted by user.{Colors.RESET}")
        sys.exit(130)
    except Exception as exc:
        print(f"{Colors.RED}Critical error: {exc}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
