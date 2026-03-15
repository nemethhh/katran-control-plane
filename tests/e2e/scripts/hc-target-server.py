#!/usr/bin/env python3
"""
HC target server: captures IPIP-encapsulated health check probes via raw socket
and exposes them over HTTP for E2E test verification.

Endpoints:
  GET  /health        -> {"status": "healthy"}
  GET  /probes        -> {"probes": [...], "count": N}
  POST /probes/reset  -> {"status": "reset"}
"""

import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

captured_probes: list[dict] = []
probes_lock = threading.Lock()


def _capture_thread():
    """Capture IPIP packets (protocol 4 = IPv4-in-IPv4, 41 = IPv6-in-IPv4)."""
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        raw.bind(("eth0", 0))
    except OSError as e:
        print(f"Warning: Could not open raw socket: {e}", flush=True)
        return

    print("Capture thread started on eth0", flush=True)

    while True:
        try:
            data, _ = raw.recvfrom(65535)
            if len(data) < 34:  # Ethernet (14) + outer IP (20)
                continue

            # Skip Ethernet header (14 bytes)
            eth_proto = struct.unpack("!H", data[12:14])[0]
            if eth_proto != 0x0800:  # Not IPv4
                continue

            ip_start = 14
            outer_ihl = (data[ip_start] & 0x0F) * 4
            outer_proto = data[ip_start + 9]

            # Protocol 4 = IPIP (IPv4-in-IPv4), 41 = IPv6-in-IPv4
            if outer_proto not in (4, 41):
                continue

            outer_src = socket.inet_ntoa(data[ip_start + 12 : ip_start + 16])
            outer_dst = socket.inet_ntoa(data[ip_start + 16 : ip_start + 20])

            inner_start = ip_start + outer_ihl
            if outer_proto == 4 and len(data) >= inner_start + 20:
                inner_src = socket.inet_ntoa(data[inner_start + 12 : inner_start + 16])
                inner_dst = socket.inet_ntoa(data[inner_start + 16 : inner_start + 20])
                inner_proto = data[inner_start + 9]
            elif outer_proto == 41 and len(data) >= inner_start + 40:
                inner_src = socket.inet_ntop(
                    socket.AF_INET6, data[inner_start + 8 : inner_start + 24]
                )
                inner_dst = socket.inet_ntop(
                    socket.AF_INET6, data[inner_start + 24 : inner_start + 40]
                )
                inner_proto = data[inner_start + 6]
            else:
                continue

            probe = {
                "outer_src": outer_src,
                "outer_dst": outer_dst,
                "inner_src": inner_src,
                "inner_dst": inner_dst,
                "proto": inner_proto,
                "timestamp": time.time(),
            }

            with probes_lock:
                captured_probes.append(probe)

        except Exception:
            pass


class HcTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "healthy"})
            return

        if self.path == "/probes":
            with probes_lock:
                probes_copy = list(captured_probes)
            self._respond(200, {"probes": probes_copy, "count": len(probes_copy)})
            return

        self._respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/probes/reset":
            with probes_lock:
                captured_probes.clear()
            self._respond(200, {"status": "reset"})
            return

        self._respond(404, {"error": "not found"})

    def _respond(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


class DualStackHTTPServer(HTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def main():
    capturer = threading.Thread(target=_capture_thread, daemon=True)
    capturer.start()

    server = DualStackHTTPServer(("::", 8080), HcTargetHandler)
    print("HC target server listening on [::]:8080 (dual-stack)", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
