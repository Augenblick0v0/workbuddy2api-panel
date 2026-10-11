"""Local candidate-image acceptance only. Synthetic HTTP/SOCKS proxy and counter.

Run inside an isolated Docker network; expose no upstream ports to the host.
No listener forwards traffic to the internet. SOCKS accepts synthetic credentials
from FIXTURE_SOCKS_USER/FIXTURE_SOCKS_PASSWORD when configured.
"""
import json
import os
import secrets
import select
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

counts = {"proxy": 0, "direct": 0, "socks": 0, "socks_targets": {}, "paths": {}}
lock = threading.Lock()
proxy_server = None
socks_server = None


def read_exact(conn, length):
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("fixture connection closed")
        data += chunk
    return data


class SocksFixture(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(15)
        try:
            version, count = read_exact(conn, 2)
            if version != 5:
                return
            methods = read_exact(conn, count)
            user = os.environ.get("FIXTURE_SOCKS_USER", "").encode()
            password = os.environ.get("FIXTURE_SOCKS_PASSWORD", "").encode()
            method = 2 if user or password else 0
            if method not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(bytes((5, method)))
            if method == 2:
                auth_version, user_length = read_exact(conn, 2)
                given_user = read_exact(conn, user_length)
                given_password = read_exact(conn, read_exact(conn, 1)[0])
                authenticated = (
                    auth_version == 1
                    and bool(user_length)
                    and secrets.compare_digest(given_user, user)
                    and secrets.compare_digest(given_password, password)
                )
                conn.sendall(bytes((1, 0 if authenticated else 1)))
                if not authenticated:
                    return
            version, command, reserved, address_type = read_exact(conn, 4)
            if version != 5 or command != 1 or reserved != 0:
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, read_exact(conn, 4))
            elif address_type == 3:
                host = read_exact(conn, read_exact(conn, 1)[0]).decode("ascii", "replace")
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(conn, 16))
            else:
                conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            port = struct.unpack("!H", read_exact(conn, 2))[0]
            # Record the requested destination, but never resolve or dial it.
            # Every successful tunnel terminates at the local HTTP fixture.
            with socket.create_connection(("127.0.0.1", 18888), timeout=5) as upstream:
                with lock:
                    counts["socks"] += 1
                    target = f"{host}:{port}"
                    counts["socks_targets"][target] = counts["socks_targets"].get(target, 0) + 1
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 18888))
                while True:
                    ready, _, _ = select.select([conn, upstream], [], [], 15)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is conn else conn).sendall(data)
        except (OSError, ValueError):
            # No request, proxy authentication, or token data is logged.
            return


class SocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


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
                for server in (socks_server, proxy_server):
                    if server is not None:
                        server.shutdown()
                        server.server_close()
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
    proxy_server = ThreadingHTTPServer(("0.0.0.0", 18888), Fixture)
    socks_server = SocksServer(("0.0.0.0", 18890), SocksFixture)
    threading.Thread(target=proxy_server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    threading.Thread(target=socks_server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 18889), Fixture).serve_forever()
