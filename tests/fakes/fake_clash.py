"""Поддельный clash API на 127.0.0.1 для тестов: формы ответов sing-box 1.14.3 (отчёт спайка, раздел 6)."""
from __future__ import annotations

import json
import queue
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeClash:
    def __init__(self, secret: str = "s3cret-token"):
        self.secret = secret
        self.proxies: dict[str, dict] = {
            "proxy": {"type": "Selector", "name": "proxy", "udp": True, "history": [], "now": "srv-a",
                      "all": ["srv-a", "srv-b", "auto"]},
            "bypass": {"type": "Selector", "name": "bypass", "udp": True, "history": [], "now": "proxy",
                       "all": ["direct", "proxy"]},
            "auto": {"type": "URLTest", "name": "auto", "udp": True, "history": [], "now": "srv-b",
                     "all": ["srv-a", "srv-b"]},
            "srv-a": {"type": "VLESS", "name": "srv-a", "udp": True, "history": []},
            "srv-b": {"type": "Hysteria2", "name": "srv-b", "udp": True, "history": []},
            "direct": {"type": "Direct", "name": "direct", "udp": True, "history": []},
        }
        # имя → мс | "timeout" | "error"; чего нет — "error"
        self.delays: dict[str, int | str] = {"srv-a": 87, "srv-b": "timeout"}
        self.connections = {"downloadTotal": 0, "uploadTotal": 0, "connections": [], "memory": 1024}
        self.closed = 0
        self.requests: list[tuple[str, str]] = []
        self.traffic: queue.Queue = queue.Queue()
        self._server: ThreadingHTTPServer | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    def start(self) -> "FakeClash":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):   # тише в выводе pytest
                pass

            def _send(self, code: int, body=None):
                payload = b"" if body is None else json.dumps(body).encode("utf-8")
                self.send_response(code)
                if payload:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def _route(self, method: str):
                parts = urllib.parse.urlsplit(self.path)
                path = urllib.parse.unquote(parts.path)
                query = dict(urllib.parse.parse_qsl(parts.query))
                fake.requests.append((method, path))
                if self.headers.get("Authorization") != f"Bearer {fake.secret}":
                    return self._send(401, {"message": "Unauthorized"})
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"null") if length else None
                return fake.handle(self, method, path, query, body)

            def do_GET(self):
                self._route("GET")

            def do_PUT(self):
                self._route("PUT")

            def do_DELETE(self):
                self._route("DELETE")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05},
                         name="fake-clash", daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self.traffic.put(None)
            self._server.shutdown()
            self._server.server_close()

    # ---------------------------------------------------------------- ответы

    def handle(self, h, method: str, path: str, query: dict, body):
        if path == "/version" and method == "GET":
            return h._send(200, {"version": "sing-box 1.14.3", "premium": True, "meta": True})
        if path == "/connections":
            if method == "DELETE":
                self.closed += 1
                return h._send(204)
            return h._send(200, self.connections)
        if path == "/traffic":
            return self._stream(h)
        if path == "/proxies":
            return h._send(200, {"proxies": self.proxies})
        if path.startswith("/group/") and path.endswith("/delay"):
            if "timeout" not in query:
                return h._send(400, {"message": "Body invalid"})
            group = self.proxies.get(path[len("/group/"):-len("/delay")])
            if group is None:
                return h._send(404, {"message": "Resource not found"})
            ok = {m: self.delays[m] for m in group.get("all", []) if isinstance(self.delays.get(m), int)}
            return h._send(200, ok)
        if path.startswith("/proxies/"):
            rest = path[len("/proxies/"):]
            if rest.endswith("/delay"):
                return self._delay(h, rest[:-len("/delay")], query)
            item = self.proxies.get(rest)
            if item is None:
                return h._send(404, {"message": "Resource not found"})
            if method == "PUT":
                if item["type"] != "Selector":
                    return h._send(400, {"message": "Must be a Selector"})
                if not isinstance(body, dict) or body.get("name") not in item["all"]:
                    return h._send(400, {"message": "Selector update error: not found"})
                item["now"] = body["name"]
                return h._send(204)
            return h._send(200, item)
        return h._send(404, {"message": "Resource not found"})

    def _delay(self, h, name: str, query: dict):
        if name not in self.proxies:
            return h._send(404, {"message": "Resource not found"})
        if "timeout" not in query:
            return h._send(400, {"message": "Body invalid"})
        result = self.delays.get(name, "error")
        if result == "timeout":
            return h._send(504, {"message": "Timeout"})
        if result == "error" or result == 0:
            return h._send(503, {"message": "An error occurred in the delay test"})
        return h._send(200, {"delay": result})

    def _stream(self, h):
        h.send_response(200)
        h.send_header("Content-Type", "application/json")
        h.end_headers()
        while True:
            item = self.traffic.get()
            if item is None:
                return
            h.wfile.write((json.dumps(item) + "\n").encode("utf-8"))
            h.wfile.flush()
