"""Local candidate-image acceptance only. Synthetic HTTP proxy and direct counter.

Run inside an isolated Docker network; expose no upstream ports to the host.
Neither listener forwards traffic to the internet or accepts real credentials.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

counts = {"proxy": 0, "direct": 0, "paths": {}}
lock = threading.Lock()


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        if path == "/fixture/break-proxy" and self.server.server_port == 18888:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"proxy stopping")
            def stop():
                self.server.shutdown()
                self.server.server_close()
            threading.Thread(target=stop, daemon=True).start()
            return
        if path == "/fixture/counts":
            with lock:
                payload = json.dumps(counts).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(payload)
            return
        with lock:
            label = "proxy" if self.server.server_port == 18888 else "direct"
            counts[label] += 1
            counts["paths"][path] = counts["paths"].get(path, 0) + 1
        if self.server.server_port == 18889:
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(200)
        if path.endswith("/chat/completions"):
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(
                b'data: {"id":"candidate-fixture","object":"chat.completion.chunk",'
                b'"choices":[{"index":0,"delta":{"content":"candidate fixture ok"}}]}\n\n'
                b'data: [DONE]\n\n'
            )
            return
        data = {}
        if "token/refresh" in path:
            data = {"accessToken": "synthetic-rotated", "refreshToken": "synthetic-refresh-rotated", "expiresIn": 7200}
        elif "get-enterprise-user-usage" in path:
            data = {"limitNum": 1000, "credit": 1}
        elif "models" in path or "config" in path:
            data = {"models": [{"id": "glm-5.2", "name": "glm-5.2", "maxInputTokens": 8192, "maxOutputTokens": 1024}]}
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"code": 0, "data": data}).encode())


if __name__ == "__main__":
    proxy = ThreadingHTTPServer(("0.0.0.0", 18888), Fixture)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 18889), Fixture).serve_forever()
