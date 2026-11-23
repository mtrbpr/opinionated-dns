#!/usr/bin/env python3
"""RFC 8484 DNS-over-HTTPS front for the resolver on 127.0.0.1:53."""

import base64
import socket
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

UPSTREAM = ("127.0.0.1", 53)
LISTEN = ("127.0.0.1", 8053)
MAX_DNS = 65535
TIMEOUT = 8


def read_exact(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def query_upstream(payload: bytes) -> bytes:
    with socket.create_connection(UPSTREAM, timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        size = struct.unpack("!H", read_exact(sock, 2))[0]
        if size == 0 or size > MAX_DNS:
            raise ValueError("bad length")
        return read_exact(sock, size)


def decode_dns_param(url: str) -> bytes | None:
    raw = parse_qs(urlsplit(url).query).get("dns", [None])[0]
    if not raw:
        return None
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        return base64.urlsafe_b64decode(padded)
    except ValueError:
        return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if urlsplit(self.path).path.rstrip("/") != "/dns-query":
            self.send_error(404)
            return
        payload = decode_dns_param(self.path)
        if payload is None:
            self.send_error(400)
            return
        self.respond(payload)

    def do_POST(self) -> None:
        if urlsplit(self.path).path.rstrip("/") != "/dns-query":
            self.send_error(404)
            return
        kind = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if kind != "application/dns-message":
            self.send_error(415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 12 or length > MAX_DNS:
            self.send_error(400)
            return
        payload = self.rfile.read(length)
        if len(payload) != length:
            self.send_error(400)
            return
        self.respond(payload)

    def respond(self, payload: bytes) -> None:
        if len(payload) < 12:
            self.send_error(400)
            return
        try:
            answer = query_upstream(payload)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(answer)))
        self.send_header("Cache-Control", "max-age=30")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()


if __name__ == "__main__":
    main()
