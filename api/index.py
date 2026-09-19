"""Vercel serverless entrypoint.

The whole detection engine runs inside this function. That is only possible
because the engine has no third-party dependencies — there is nothing to
install, so the bundle is a few hundred kilobytes of Python and the cold start
is the interpreter itself.
"""
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from web.router import MAX_UPLOAD, dispatch      # noqa: E402


class handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _run(self, body: bytes = b"") -> None:
        path, _, query = self.path.partition("?")
        status, headers, raw = dispatch(self.command, path, query, body)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def do_GET(self):
        self._run()

    def do_OPTIONS(self):
        self._run()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self._run(self.rfile.read(min(n, MAX_UPLOAD + 1)) if n else b"")

    def log_message(self, *a):
        pass
