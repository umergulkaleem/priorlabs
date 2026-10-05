"""Generate bounded, unseen live traffic for IDS validation.

Self-to-self connections are often routed internally on Windows and do not
appear on a physical Wi-Fi adapter. This harness therefore makes a small,
deterministic sequence of ordinary outbound TCP flows to one explicitly
chosen host. The flows are generated at runtime and are not copied from the
training dataset. It is not a scanner, exploit, or flood.

This validates capture, flow reconstruction, feature extraction, and
inference on unseen traffic. It does not guarantee an attack prediction:
the live extractor uses flow statistics, not application payload semantics.
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
        default=6,
        help="Maximum connections to generate (1-10).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Delay between connections in seconds.",
    )
    args = parser.parse_args()
    if args.connections < 1 or args.connections > 10:
        raise SystemExit("--connections must be between 1 and 10.")
    if args.delay < 0.05 or args.delay > 5:
        raise SystemExit("--delay must be between 0.05 and 5 seconds.")

    interface = discover_interfaces()[0]
    addresses = socket.getaddrinfo(args.target, None, socket.AF_INET, socket.SOCK_STREAM)
    target_ip = addresses[0][4][0]
    ports = [80, 443]
    request_sizes = [64, 256, 768, 1536]

    print("Bounded unseen outbound validation traffic; not a real attack.")
    print("Traffic is generated at runtime and is not replayed from training data.")
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
                    padding = "x" * request_sizes[index % len(request_sizes)]
                    connection.sendall(
                        f"GET /ids-live-check-{index} HTTP/1.1\r\n"
                        f"Host: {args.target}\r\n"
                        f"X-IDS-Test-Padding: {padding}\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    connection.recv(1024)
                else:
                    # A short TLS-port connection creates a distinct flow
                    # without sending exploit data or scanning the target.
                    connection.sendall(b"\x16\x03\x01\x00\x2f" + b"\x00" * 47)
                completed += 1
                print(f"Captured candidate flow {index + 1}: {target_ip}:{port}")
        except (OSError, TimeoutError) as error:
            print(f"Connection {index + 1} to {target_ip}:{port} was unavailable: {error}")
        time.sleep(args.delay)

    print(f"Validation traffic complete: {completed}/{args.connections} connections completed.")
    print("Review LIVE ACTIVITY; stop monitoring only after the flows appear.")


if __name__ == "__main__":
    main()
