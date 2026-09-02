#!/usr/bin/env python3
"""Serve a directory of wheels as a PEP 503 index over mTLS, for smoke tests.

Clients must present a certificate signed by --client-ca. Binds an ephemeral
port and writes it to --port-file once the server is listening.
"""

import argparse
import re
import socketserver
import ssl
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class LoopbackHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse-DNS lookup at bind time.

    `HTTPServer.server_bind` resolves the bind address with
    `socket.getfqdn()`, which can block for tens of seconds on runners with
    slow resolvers (notably GitHub's macOS runners). The name only feeds
    response headers, so hardcode it for the loopback bind.
    """

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.socket.getsockname()[1]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def collect(directory: Path) -> dict[str, list[Path]]:
    packages: dict[str, list[Path]] = {}
    for wheel in sorted(directory.glob("*.whl")):
        project = normalize(wheel.name.split("-", 1)[0])
        packages.setdefault(project, []).append(wheel)
    return packages


class IndexHandler(BaseHTTPRequestHandler):
    server_version = "pkcs11-smoke-index/1.0"
    packages: dict[str, list[Path]] = {}

    def log_message(self, *args):  # quiet
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.path == "/simple/":
            links = "".join(
                f'<a href="/simple/{escape(name)}/">{escape(name)}</a>'
                for name in self.packages
            )
            self._send(
                200,
                f"<!doctype html><html><body>{links}</body></html>".encode(),
                "text/html",
            )
            return
        project = re.fullmatch(r"/simple/([^/]+)/", self.path)
        if project:
            files = self.packages.get(normalize(project.group(1)))
            if files is None:
                self._send(404, b"unknown project", "text/plain")
                return
            links = "".join(
                f'<a href="/files/{escape(f.name)}">{escape(f.name)}</a>' for f in files
            )
            self._send(
                200,
                f"<!doctype html><html><body>{links}</body></html>".encode(),
                "text/html",
            )
            return
        artifact = re.fullmatch(r"/files/([^/]+)", self.path)
        if artifact:
            for files in self.packages.values():
                for f in files:
                    if f.name == artifact.group(1):
                        self._send(200, f.read_bytes(), "application/octet-stream")
                        return
        self._send(404, b"not found", "text/plain")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", required=True, type=Path)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--port-file", required=True, type=Path)
    args = parser.parse_args()

    IndexHandler.packages = collect(args.packages)
    if not IndexHandler.packages:
        raise SystemExit(f"no wheels found in {args.packages}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED

    server = LoopbackHTTPServer(("127.0.0.1", 0), IndexHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    args.port_file.write_text(str(server.server_address[1]))
    print(f"serving on 127.0.0.1:{server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
