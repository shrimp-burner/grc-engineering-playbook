"""Receive signed webhooks: verify the signature, dedupe replays, persist the raw payload.

The security-relevant functions are pure and unit-tested. `serve()` runs a small
threading HTTP server for demos.
"""
from __future__ import annotations

import hashlib
import hmac
import base64
import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPLAY_WINDOW_SECONDS = 300


def expected_signature(secret: bytes, timestamp: str, body: bytes) -> str:
    """Canonical signing string: '<timestamp>.<body>'."""
    return hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, timestamp: str, body: bytes, provided: str, window: int = REPLAY_WINDOW_SECONDS):
    if not provided:
        return False, "missing signature header"
    exp = expected_signature(secret, timestamp, body)
    try:
        if not hmac.compare_digest(exp, provided.strip()):
            return False, "signature mismatch"
    except TypeError:
        # compare_digest raises on non-ASCII str input; treat as a malformed header.
        return False, "malformed signature header"
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False, "malformed timestamp"
    age = abs(time.time() - ts)
    if age > window:
        return False, "stale timestamp ({0}s > {1}s window)".format(int(age), window)
    return True, "ok"


class ReceiverState:
    """Holds mutable state so the verify/dedupe/persist flow can be tested in isolation."""

    def __init__(self, events_file: Path, seen_file: Path):
        self.events_file = Path(events_file)
        self.seen_file = Path(seen_file)
        self._lock = threading.Lock()

    def _seen(self):
        if self.seen_file.exists():
            return json.loads(self.seen_file.read_text())
        return {}

    def _save_seen(self, seen):
        # Atomic replace: a concurrent reader never sees a half-written file.
        tmp = self.seen_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(seen, indent=1))
        os.replace(tmp, self.seen_file)

    def handle(self, secret: bytes, headers: dict, body: bytes, window: int = REPLAY_WINDOW_SECONDS):
        ts = headers.get("X-Timestamp", "")
        sig = headers.get("X-Signature", "").strip()
        event_id = headers.get("X-Event-Id", "")

        ok, reason = verify_signature(secret, ts, body, sig, window)
        if not ok:
            return 401, {"status": "rejected", "reason": reason}

        # The read-check-write of the dedupe ledger is serialized, because the server
        # is threaded: without the lock, concurrent replays of one request slip through.
        with self._lock:
            seen = self._seen()
            if sig in seen:
                return 200, {"status": "duplicate", "event_id": event_id, "first_seen": seen[sig]}
            now = datetime.now(timezone.utc).isoformat()
            # Persist the raw bytes before parsing. The raw payload is the evidence and
            # survives a malformed body.
            with self.events_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"received_at": now, "event_id": event_id,
                                    "raw_b64": base64.b64encode(body).decode("ascii")}) + "\n")
            seen[sig] = now
            self._save_seen(seen)

        try:
            json.loads(body)
        except json.JSONDecodeError:
            return 400, {"status": "rejected", "reason": "body is not valid JSON", "persisted": True}
        return 200, {"status": "received", "event_id": event_id}


class _Handler(BaseHTTPRequestHandler):
    state = None
    secret = b"dev-shared-secret-change-me"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        headers = {k: v for k, v in self.headers.items()}
        status, resp = self.state.handle(self.secret, headers, body)
        data = json.dumps(resp).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def serve(port=8765, workdir=None, secret=None):
    workdir = Path(workdir or ".")
    workdir.mkdir(parents=True, exist_ok=True)
    env_secret = os.environ.get("GRC_WEBHOOK_SECRET")
    if secret is not None:
        _Handler.secret = secret if isinstance(secret, bytes) else secret.encode()
    elif env_secret:
        _Handler.secret = env_secret.encode()
        print("secret loaded from GRC_WEBHOOK_SECRET")
    else:
        print("WARNING: GRC_WEBHOOK_SECRET unset; using the development default")
    _Handler.state = ReceiverState(workdir / "events.jsonl", workdir / "seen_events.json")
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print("webhook receiver on http://127.0.0.1:{0}".format(port))
    srv.serve_forever()


if __name__ == "__main__":
    serve()
