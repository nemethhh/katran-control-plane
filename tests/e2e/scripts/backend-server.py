#!/usr/bin/env python3
"""
Simple HTTP server for E2E backend containers.

Returns JSON identifying the backend so tests can verify which backend
handled each request. Also counts requests for distribution tests.
"""

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

BACKEND_NAME = os.environ.get("BACKEND_NAME", "unknown")
BACKEND_ADDR = os.environ.get("BACKEND_ADDR", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "80"))

request_count = 0
count_lock = threading.Lock()

# Tunnel outer-src tracking for encap source IP verification
last_tunnel_src = {"outer_src": None, "last_seen": 0.0}
tunnel_lock = threading.Lock()


def _sniff_tunnel():
    """Background thread: sniff IPIP packets on tunl0, record outer source IP."""
    import time

    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        raw.bind(("tunl0", 0))
    except OSError:
        print("Warning: Could not bind to tunl0 for tunnel sniffing", flush=True)
        return

    while True:
        try:
            data, _ = raw.recvfrom(65535)
            if len(data) < 20:
                continue
            # Parse outer IPv4 header source address (bytes 12-16)
            src_ip = socket.inet_ntoa(data[12:16])
            with tunnel_lock:
                last_tunnel_src["outer_src"] = src_ip
                last_tunnel_src["last_seen"] = time.time()
        except Exception:
            pass


class BackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global request_count

        if self.path == "/health":
            self._respond(200, {"status": "healthy", "backend": BACKEND_NAME})
            return

        if self.path == "/stats":
            with count_lock:
                count = request_count
            self._respond(200, {"backend": BACKEND_NAME, "requests": count})
            return

        if self.path == "/tunnel-info":
            with tunnel_lock:
                info = dict(last_tunnel_src)
            self._respond(200, info)
            return

        # Default: identify this backend
        with count_lock:
            request_count += 1
            count = request_count

        self._respond(
            200,
            {
                "backend": BACKEND_NAME,
                "address": BACKEND_ADDR,
                "request_number": count,
            },
        )

    def _respond(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Backend", BACKEND_NAME)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        # Quiet logging – only errors
        pass


class DualStackHTTPServer(HTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def main():
    server = DualStackHTTPServer(("::", HTTP_PORT), BackendHandler)
    print(f"Backend {BACKEND_NAME} listening on [::]:{HTTP_PORT} (dual-stack)", flush=True)
    sniffer = threading.Thread(target=_sniff_tunnel, daemon=True)
    sniffer.start()
    server.serve_forever()


if __name__ == "__main__":
    main()
