import base64
import json
import tempfile
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grc_playbook.webhook import ReceiverState, expected_signature, verify_signature

SECRET = b"test-secret"


def _headers(body, ts=None, event_id="evt-1"):
    t = str(ts if ts is not None else int(time.time()))
    return {"X-Event-Id": event_id, "X-Timestamp": t,
            "X-Signature": expected_signature(SECRET, t, body)}


def test_valid_signature_accepted():
    body = json.dumps({"type": "control.failed"}).encode()
    h = _headers(body)
    ok, why = verify_signature(SECRET, h["X-Timestamp"], body, h["X-Signature"])
    assert ok, why


def test_tampered_body_rejected():
    body = json.dumps({"type": "control.failed"}).encode()
    h = _headers(body)
    ok, why = verify_signature(SECRET, h["X-Timestamp"], body + b" ", h["X-Signature"])
    assert not ok and "mismatch" in why


def test_stale_timestamp_rejected():
    body = b"{}"
    old = str(int(time.time()) - 360)
    sig = expected_signature(SECRET, old, body)
    ok, why = verify_signature(SECRET, old, body, sig)
    assert not ok and "stale" in why


def test_wrong_secret_rejected():
    body = b"{}"
    h = _headers(body)
    ok, _ = verify_signature(b"other", h["X-Timestamp"], body, h["X-Signature"])
    assert not ok


def test_receiver_dedupes_a_replay():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        state = ReceiverState(tmp / "events.jsonl", tmp / "seen.json")
        body = json.dumps({"type": "x"}).encode()
        h = _headers(body)
        code1, r1 = state.handle(SECRET, h, body)
        code2, r2 = state.handle(SECRET, h, body)
        assert code1 == 200 and r1["status"] == "received"
        assert code2 == 200 and r2["status"] == "duplicate"
        assert len((tmp / "events.jsonl").read_text().strip().splitlines()) == 1


def test_replay_with_a_new_event_id_is_still_deduped():
    # The event-id header is attacker-controlled, so dedupe is keyed on the
    # signature. Replaying the same signed request under a fresh header must not
    # create a second event.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        state = ReceiverState(tmp / "events.jsonl", tmp / "seen.json")
        body = json.dumps({"type": "x"}).encode()
        ts = str(int(time.time()))
        sig = expected_signature(SECRET, ts, body)
        h1 = {"X-Event-Id": "evt-real", "X-Timestamp": ts, "X-Signature": sig}
        h2 = {"X-Event-Id": "evt-attacker", "X-Timestamp": ts, "X-Signature": sig}
        first = state.handle(SECRET, h1, body)
        replay = state.handle(SECRET, h2, body)
        assert first[1]["status"] == "received"
        assert replay[1]["status"] == "duplicate"
        assert len((tmp / "events.jsonl").read_text().strip().splitlines()) == 1


def test_raw_body_is_persisted_before_parsing():
    # D3: the raw payload is the evidence. A correctly signed but malformed body
    # must still be written to disk, even though the handler rejects it.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        state = ReceiverState(tmp / "events.jsonl", tmp / "seen.json")
        body = b"{not json"
        ts = str(int(time.time()))
        sig = expected_signature(SECRET, ts, body)
        code, resp = state.handle(SECRET, {"X-Event-Id": "e", "X-Timestamp": ts, "X-Signature": sig}, body)
        assert code == 400 and resp.get("persisted") is True
        record = json.loads((tmp / "events.jsonl").read_text().strip())
        assert base64.b64decode(record["raw_b64"]) == body
