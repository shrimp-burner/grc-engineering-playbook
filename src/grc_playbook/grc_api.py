"""A client for a GRC product API: auth, cursor pagination, retries, idempotency.

Bearer auth, cursor pagination, retry with exponential backoff and jitter on
429/5xx, idempotency keys on writes, and HMAC webhook verification.
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request


class GrcApiError(Exception):
    pass


class GrcClient:
    def __init__(self, base_url, token, max_retries=5, timeout=10, verbose=True):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.max_retries = max_retries
        self.timeout = timeout
        self.verbose = verbose

    def _log(self, msg):
        if self.verbose:
            print("  [client] " + msg)

    def _request(self, method, path, params=None, body=None, idempotency_key=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        data = json.dumps(body).encode() if body is not None else None
        attempt = 0
        while attempt <= self.max_retries:
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode() or "{}")
            except urllib.error.HTTPError as e:
                if e.code == 429 or 500 <= e.code < 600:
                    ra = e.headers.get("Retry-After")
                    delay = int(ra) if (ra and ra.isdigit()) else min(2 ** attempt, 30)
                    delay += random.random()
                    self._log("HTTP {0} on {1} -> backoff {2:.1f}s (attempt {3}/{4})".format(e.code, path, delay, attempt + 1, self.max_retries))
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise GrcApiError("HTTP {0} on {1}: {2}".format(e.code, path, e.read().decode()[:200]))
            except urllib.error.URLError as e:
                self._log("network error on {0} -> retrying ({1})".format(path, e.reason))
                time.sleep(min(2 ** attempt, 30) + random.random())
                attempt += 1
                continue
        raise GrcApiError("exhausted retries on " + path)

    def paginate(self, path, params=None, max_pages=1000):
        """Follow next_cursor to exhaustion, with a hard cap so a misbehaving server
        that always returns a cursor cannot loop forever."""
        items, cursor, pages = [], None, 0
        while True:
            p = dict(params or {})
            if cursor:
                p["cursor"] = cursor
            page = self._request("GET", path, p)
            items.extend(page.get("items", []))
            pages += 1
            cursor = page.get("next_cursor")
            if not cursor:
                break
            if pages >= max_pages:
                raise GrcApiError("pagination exceeded {0} pages on {1}".format(max_pages, path))
        self._log("{0} -> {1} item(s) across {2} page(s)".format(path, len(items), pages))
        return items

    def get_controls(self):
        return self.paginate("/v1/controls")

    def get_findings(self):
        return self.paginate("/v1/findings")

    def create_ticket(self, finding_id, title, idempotency_key):
        return self._request("POST", "/v1/tickets",
                             body={"finding_id": finding_id, "title": title},
                             idempotency_key=idempotency_key)


def verify_webhook(secret: bytes, timestamp: str, body: bytes, signature: str, window=300):
    """Boolean wrapper around webhook.verify_signature, so the HMAC scheme lives in
    exactly one place."""
    from grc_playbook.webhook import verify_signature
    ok, _ = verify_signature(secret, timestamp, body, signature, window)
    return ok
