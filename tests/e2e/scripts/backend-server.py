#!/usr/bin/env python3
"""
Simple HTTP server for E2E backend containers.

Returns JSON identifying the backend so tests can verify which backend
handled each request. Also counts requests for distribution tests.
"""

import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


BACKEND_NAME = os.environ.get("BACKEND_NAME", "unknown")
BACKEND_ADDR = os.environ.get("BACKEND_ADDR", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "80"))

request_count = 0
count_lock = threading.Lock()


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

        # Default: identify this backend
        with count_lock:
            request_count += 1
            count = request_count

        self._respond(200, {
            "backend": BACKEND_NAME,
            "address": BACKEND_ADDR,
            "request_number": count,
        })

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


def main():
    server = HTTPServer(("0.0.0.0", HTTP_PORT), BackendHandler)
    print(f"Backend {BACKEND_NAME} listening on 0.0.0.0:{HTTP_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
