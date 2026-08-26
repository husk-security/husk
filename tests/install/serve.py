#!/usr/bin/env python3
"""Tiny localhost HTTPS file server for install.sh end-to-end tests.

It serves a directory tree over TLS with a self-signed cert so the installer's
hardened download path (`curl --proto '=https' --tlsv1.2`) exercises its real
code path against a local mock of GitHub: no live network, no real release.

Usage: serve.py <root-dir> <cert.pem> <key.pem> <port-file>

Binds 127.0.0.1 on an ephemeral port and writes the chosen port to <port-file>
so the caller can discover it. Runs until killed.
"""

import functools
import http.server
import socketserver
import ssl
import sys


def main() -> None:
    root, cert, key, port_file = sys.argv[1:5]

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=root
    )

    # Port 0 => the OS picks a free ephemeral port; we report it back.
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    port = httpd.socket.getsockname()[1]
    with open(port_file, "w", encoding="utf-8") as fh:
        fh.write(str(port))

    httpd.serve_forever()


if __name__ == "__main__":
    main()
