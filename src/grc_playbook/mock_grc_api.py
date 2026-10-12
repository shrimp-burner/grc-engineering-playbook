"""A local mock of a GRC product API (stdlib only), used by the tests and the `mock-api` command.

Mimics real-world friction: bearer auth, cursor pagination, 429 throttling with
Retry-After, and idempotent writes keyed by Idempotency-Key.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "test-token"
PAGE_SIZE = 2
RATE_LIMIT_EVERY = 4

CONTROLS = [
    {"id": "CC6.1", "title": "Logical access controls", "framework": "SOC2", "owner_team": "cloud-security"},
    {"id": "CC7.2", "title": "Monitoring & detection", "framework": "SOC2", "owner_team": "cloud-security"},
    {"id": "A.8.13", "title": "Information backup", "framework": "ISO27001", "owner_team": "platform"},
    {"id": "A.5.15", "title": "Access control policy", "framework": "ISO27001", "owner_team": "identity"},
    {"id": "CC6.6", "title": "Secure configuration", "framework": "SOC2", "owner_team": "platform"},
]
FINDINGS = [
    {"id": "F-1001", "control_id": "CC6.1", "asset": "s3://acme-prod-backup", "severity": "high", "status": "open"},
    {"id": "F-1002", "control_id": "CC6.6", "asset": "sg-app-01", "severity": "critical", "status": "open"},
    {"id": "F-1003", "control_id": "A.8.13", "asset": "ebs-vol-app-01", "severity": "medium", "status": "open"},
    {"id": "F-1004", "control_id": "CC7.2", "asset": "acme-shared", "severity": "high", "status": "open"},
    {"id": "F-1005", "control_id": "A.5.15", "asset": "iam-role-deployer", "severity": "medium", "status": "open"},
]

STATE = {"calls": 0, "tickets": {}}


def _page(items, cursor):
    start = int(cursor or 0)
    chunk = items[start:start + PAGE_SIZE]
    nxt = start + PAGE_SIZE
    return {"items": chunk, "next_cursor": (str(nxt) if nxt < len(items) else None)}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        return self.headers.get("Authorization") == "Bearer " + TOKEN

    def do_GET(self):
        STATE["calls"] += 1
        if STATE["calls"] % RATE_LIMIT_EVERY == 0:
            return self._send(429, {"error": "rate limited"}, {"Retry-After": "1"})
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        path, _, query = self.path.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        if path == "/v1/controls":
            return self._send(200, _page(CONTROLS, params.get("cursor")))
        if path == "/v1/findings":
            return self._send(200, _page(FINDINGS, params.get("cursor")))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        STATE["calls"] += 1
        if STATE["calls"] % RATE_LIMIT_EVERY == 0:
            return self._send(429, {"error": "rate limited"}, {"Retry-After": "1"})
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/v1/tickets":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        key = self.headers.get("Idempotency-Key")
        if not key:
            return self._send(400, {"error": "Idempotency-Key required"})
        if key in STATE["tickets"]:
            return self._send(200, {"ticket_id": STATE["tickets"][key], "deduplicated": True})
        tid = "T-" + str(1000 + len(STATE["tickets"]))
        STATE["tickets"][key] = tid
        return self._send(201, {"ticket_id": tid, "finding_id": body.get("finding_id")})

    def log_message(self, *args):
        pass


def create_server(port=8770):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port=8770):
    srv = create_server(port)
    print("mock GRC API on http://127.0.0.1:{0} (token: {1})".format(port, TOKEN))
    srv.serve_forever()


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8770)
