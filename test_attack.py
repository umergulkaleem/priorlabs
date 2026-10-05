"""Generate bounded, visible test traffic for Live Network capture.

Self-to-self connections are often routed internally on Windows and do not
appear on a physical Wi-Fi adapter. This harness therefore makes a small
number of ordinary outbound TCP connections to one explicitly chosen host.
It is not a scanner, exploit, or flood.
"""

from __future__ import annotations

import argparse
import socket
import time

from src.live_network import discover_interfaces


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate bounded outbound IDS validation traffic."
    )
    parser.add_argument(
        "--target",
        default="example.com",
        help="One host you are authorized to contact (default: example.com).",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=2,
        help="Maximum connections to generate (1-5).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Delay between connections in seconds.",
    )
    args = parser.parse_args()
    if args.connections < 1 or args.connections > 5:
        raise SystemExit("--connections must be between 1 and 5.")
    if args.delay < 0.05 or args.delay > 5:
        raise SystemExit("--delay must be between 0.05 and 5 seconds.")

    interface = discover_interfaces()[0]
    addresses = socket.getaddrinfo(args.target, None, socket.AF_INET, socket.SOCK_STREAM)
    target_ip = addresses[0][4][0]
    ports = [80, 443]

    print("Bounded outbound validation traffic; not a real attack.")
    print(f"Capture interface: {interface['display_name']} ({interface['ip_address']})")
    print(f"Single authorized target: {args.target} ({target_ip})")
    print(f"Destination ports: {ports}; connections: {args.connections}")

    completed = 0
    for index in range(args.connections):
        port = ports[index % len(ports)]
        try:
            with socket.create_connection((target_ip, port), timeout=4) as connection:
                connection.settimeout(2)
                if port == 80:
                    connection.sendall(
                        f"HEAD / HTTP/1.1\r\nHost: {args.target}\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    connection.recv(1024)
                completed += 1
                print(f"Captured candidate flow {index + 1}: {target_ip}:{port}")
        except (OSError, TimeoutError) as error:
            print(f"Connection {index + 1} to {target_ip}:{port} was unavailable: {error}")
        time.sleep(args.delay)

    print(f"Validation traffic complete: {completed}/{args.connections} connections completed.")
    print("Review LIVE ACTIVITY; stop monitoring only after the flows appear.")


if __name__ == "__main__":
    main()
