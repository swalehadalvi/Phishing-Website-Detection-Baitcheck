#!/usr/bin/env python3
"""Baitcheck local helper.

Serves the Baitcheck page and one extra API that a web page cannot do on its own:
read the TLS certificate of the site you are checking.

    python server.py            then open http://127.0.0.1:8000

Needs Python 3.8+ and nothing else. It listens on 127.0.0.1 only, so other
computers on your network cannot use it. It refuses to connect to private or
local addresses unless you start it with --allow-private.
"""
import argparse
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}$", re.I)
TIMEOUT = 6
ALLOW_PRIVATE = False


def resolve(host):
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    seen, out = set(), []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append((info[0], ip))
    return out


def is_private(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified


def decode_der(der):
    """Parse a DER certificate with the standard library only."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        return ssl._ssl._test_decode_cert(path)  # CPython helper, present in 3.8 to 3.13
    finally:
        os.unlink(path)


def flatten(rdns):
    out = {}
    for rdn in rdns or ():
        for key, value in rdn:
            out[key] = value
    return out


def iso(text):
    return datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(text), datetime.timezone.utc)


def summarise(parsed, result):
    subj, iss = flatten(parsed.get("subject")), flatten(parsed.get("issuer"))
    nb, na = iso(parsed["notBefore"]), iso(parsed["notAfter"])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [v for k, v in parsed.get("subjectAltName", ()) if k == "DNS"]
    result.update(
        subject_cn=subj.get("commonName"),
        subject_org=subj.get("organizationName"),
        issuer_cn=iss.get("commonName"),
        issuer_org=iss.get("organizationName"),
        not_before=nb.date().isoformat(),
        not_after=na.date().isoformat(),
        age_days=max(0, (now - nb).days),
        days_left=(na - now).days,
        san=sans[:12],
        san_count=len(sans),
        self_signed=parsed.get("subject") == parsed.get("issuer"),
    )


def fetch_cert(host, port):
    if not HOST_RE.match(host):
        return {"error": "bad_host", "message": "That is not a valid host name."}
    try:
        addrs = resolve(host)
    except socket.gaierror:
        return {"error": "unreachable", "message": "The domain does not resolve. It may be offline or not exist."}
    if not addrs:
        return {"error": "unreachable", "message": "The domain does not resolve."}
    if not ALLOW_PRIVATE and any(is_private(ip) for _, ip in addrs):
        return {"error": "private", "message": "Private and local addresses are not checked."}
    family, ip = addrs[0]  # connect to the address we validated, not a second lookup
    result = {"host": host, "port": port, "verified": False, "verify_error": None}
    parsed = None
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                parsed = s.getpeercert()
                result["verified"] = True
                result["tls"] = s.version()
    except ssl.SSLCertVerificationError as e:
        result["verify_error"] = getattr(e, "verify_message", None) or str(e)
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((ip, port))
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    parsed = decode_der(s.getpeercert(binary_form=True))
                    result["tls"] = s.version()
        except Exception:
            return {"error": "no_details", "message": "The certificate was rejected and its details could not be read.", "verify_error": result["verify_error"]}
    except ssl.SSLError:
        return {"error": "no_tls", "message": "The server did not complete a secure (TLS) connection on this port."}
    except (socket.timeout, TimeoutError):
        return {"error": "unreachable", "message": "The server did not answer in time."}
    except OSError:
        return {"error": "unreachable", "message": "Could not connect to the server on this port."}
    try:
        summarise(parsed, result)
    except Exception:
        return {"error": "no_details", "message": "The certificate could not be read."}
    return result


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=HERE, **kw)

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/ping":
            return self._json({"ok": True})
        if u.path == "/api/cert":
            q = parse_qs(u.query)
            host = (q.get("host", [""])[0] or "").strip().lower().rstrip(".")
            try:
                port = int(q.get("port", ["443"])[0] or 443)
            except ValueError:
                port = 0
            if not host or not 1 <= port <= 65535:
                return self._json({"error": "bad_request", "message": "Missing host or invalid port."}, 400)
            return self._json(fetch_cert(host, port))
        if u.path in ("", "/"):
            self.path = "/index.html"
        return super().do_GET()

    def log_message(self, fmt, *args):
        pass


def main():
    global ALLOW_PRIVATE
    ap = argparse.ArgumentParser(description="Baitcheck local helper")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--allow-private", action="store_true", help="also check private/local addresses (for testing)")
    args = ap.parse_args()
    ALLOW_PRIVATE = args.allow_private
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Baitcheck is running at http://127.0.0.1:{args.port}  (press Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
