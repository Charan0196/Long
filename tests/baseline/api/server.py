from __future__ import annotations
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from api.client import BaseTarget
from api.models import APIRequest


class TargetHTTPHandler(BaseHTTPRequestHandler):
    target: BaseTarget

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def _handle_request(self, method: str):
        content_length = int(self.headers.get("Content-Length", 0))
        body = None
        if content_length > 0:
            raw_body = self.rfile.read(content_length)
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except Exception:
                body = None

        headers = {k: v for k, v in self.headers.items()}
        req = APIRequest(method=method, path=self.path, headers=headers, body=body)
        resp = self.target.dispatch(req)

        self.send_response(resp.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        payload = {"data": resp.data} if resp.data is not None else {"error": resp.error}
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress noisy HTTP server logs during fuzzing
        pass


class LoopbackTargetServer:
    """Manages an in-process HTTP server exposing a target API on loopback."""

    def __init__(self, target: BaseTarget, port: int = 0):
        self.target = target
        handler = type("ConfiguredHandler", (TargetHTTPHandler,), {"target": target})
        self.httpd = HTTPServer(("127.0.0.1", port), handler)
        self.host, self.port = self.httpd.server_address
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
