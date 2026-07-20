#!/usr/bin/env python3
"""dev-server.py — DEVELOPMENT ONLY. Safe to delete before publishing.

A dependency-free file watcher for live-reloading the extension while you work.

Run it from the extension folder:

    python3 dev-server.py

It serves one thing at http://127.0.0.1:5599/version — a short "token" that is
just the most-recent modified time of the extension's source files. Whenever you
save a file, the token changes; dev-reload.js (running inside the extension's
service worker) notices and reloads the extension for you. No browser clicks, no
keyboard shortcut.

Stop it with Ctrl+C. Change the port with:  PORT=6000 python3 dev-server.py
"""

import os
import http.server
import socketserver

EXT_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "5599"))

# Only these file types affect the extension; ignore everything else.
WATCH_SUFFIXES = (".js", ".json", ".html", ".css")
IGNORE_DIRS = {".git", "node_modules"}


def current_token():
    """Newest modified-time across watched files, as a string."""
    newest = 0.0
    for root, dirs, files in os.walk(EXT_DIR):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for name in files:
            if name.endswith(WATCH_SUFFIXES):
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(root, name)))
                except OSError:
                    pass
    return f"{newest:.3f}"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = current_token().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the console quiet; we only care about start/stop


def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"[dev-server] watching {EXT_DIR}")
        print(f"[dev-server] serving token at http://127.0.0.1:{PORT}/version")
        print("[dev-server] edit a file to auto-reload the extension. Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[dev-server] stopped.")


if __name__ == "__main__":
    main()
