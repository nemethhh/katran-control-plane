#!/usr/bin/env python3
"""
Send a SO_MARK-tagged UDP packet to trigger a TC-BPF health check probe.

Usage: python3 hc-probe-trigger.py <somark> <dst_addr> [dst_port]

The TC egress BPF program intercepts packets with matching SO_MARK and
rewrites them into IPIP-encapsulated HC probes.
"""

import socket
import sys


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <somark> <dst_addr> [dst_port]", file=sys.stderr)
        sys.exit(1)

    somark = int(sys.argv[1])
    dst_addr = sys.argv[2]
    dst_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999

    family = socket.AF_INET6 if ":" in dst_addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, somark)
        sock.sendto(b"hc-probe", (dst_addr, dst_port))
        print(f"Sent marked packet (somark={somark}) to {dst_addr}:{dst_port}", flush=True)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
