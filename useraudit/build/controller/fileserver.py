"""
Embedded HTTP file server (port 8080). Runs as a daemon thread.
"""

import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger("fileserver")

DATA_DIR = "/data/logs"
HEALTHZ_FILE = os.path.join(DATA_DIR, ".healthz.json")


class FileServerHandler(BaseHTTPRequestHandler):
    """Read-only file server: /healthz, /logs/, /logs/<file>"""

    def log_message(self, format, *args):
        # Only log errors, not every request
        pass

    def do_GET(self):
        path = self.path
        # Strip query string
        if "?" in path:
            path = path.split("?")[0]
        # Strip HttpProxy prefix if present (EDA forwards full path)
        proxy_prefix = "/core/httpproxy/v1/useraudit"
        if path.startswith(proxy_prefix):
            path = path[len(proxy_prefix):] or "/"

        # Normalize: strip trailing slashes but keep root as empty
        path = path.rstrip("/")

        if path == "/healthz":
            self._serve_healthz()
        elif path == "/logs" or path == "" or path == "/":
            self._serve_log_list()
        elif path.startswith("/logs/"):
            self._serve_log_file(path[6:])  # strip "/logs/"
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        self.send_error(405, "Method Not Allowed")

    def do_PUT(self):
        self.send_error(405, "Method Not Allowed")

    def do_DELETE(self):
        self.send_error(405, "Method Not Allowed")

    def do_PATCH(self):
        self.send_error(405, "Method Not Allowed")

    def _serve_healthz(self):
        try:
            with open(HEALTHZ_FILE, "r") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode("utf-8"))
        except FileNotFoundError:
            # Before first poll cycle, return a minimal OK
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"starting","last_poll":null}')

    def _serve_log_list(self):
        try:
            files = []
            for name in sorted(os.listdir(DATA_DIR)):
                if not name.endswith(".log"):
                    continue
                full = os.path.join(DATA_DIR, name)
                if not os.path.isfile(full):
                    continue
                st = os.stat(full)
                files.append({
                    "name": name,
                    "size_bytes": st.st_size,
                    "modified": st.st_mtime,
                })
            body = json.dumps(files, indent=2)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        except Exception as e:
            logger.error("Error listing logs: %s", e)
            self.send_error(500, "Internal Server Error")

    def _serve_log_file(self, filename):
        # Path traversal protection
        if ".." in filename or "/" in filename or "\\" in filename:
            self.send_error(403, "Forbidden")
            return
        full = os.path.join(DATA_DIR, filename)
        real = os.path.realpath(full)
        if not real.startswith(os.path.realpath(DATA_DIR)):
            self.send_error(403, "Forbidden")
            return
        if not os.path.isfile(real):
            self.send_error(404, "Not Found")
            return
        try:
            with open(real, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            logger.error("Error serving %s: %s", filename, e)
            self.send_error(500, "Internal Server Error")


def write_healthz(status="ok", last_poll=None):
    """Atomic write of .healthz.json via rename."""
    data = json.dumps({"status": status, "last_poll": last_poll})
    tmp = HEALTHZ_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
    os.replace(tmp, HEALTHZ_FILE)


def start_file_server(port=8080):
    """Start the HTTP file server as a daemon thread."""
    server = ThreadingHTTPServer(("0.0.0.0", port), FileServerHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name="fileserver")
    t.start()
    logger.info("File server started on port %d", port)
    return server
