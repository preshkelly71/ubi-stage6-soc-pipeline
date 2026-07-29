"""Payload handler tests."""
import sys
import os
import csv
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.sessionizer import Sessionizer
from pipeline.payload_handler import PayloadHandler


def test_payload_extraction():
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_success", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "payload_download", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z", "payload_sha256": "abc123def456"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    ph = PayloadHandler(output_dir="/tmp")
    payloads = ph.extract_payloads(sessions)
    assert len(payloads) == 1
    assert payloads[0]["payload_sha256"] == "abc123def456"
    assert payloads[0]["executed"] is False


def test_no_payload_execution():
    """Payload handler never executes payloads — only hashes them."""
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "payload_download", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z", "payload_sha256": "deadbeef"},
        {"action": "disconnect", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    ph = PayloadHandler(output_dir="/tmp")
    payloads = ph.extract_payloads(sessions)
    for p in payloads:
        assert p["executed"] is False
        assert p["quarantine_status"] == "hashed_only"


def test_hash_ledger_written(tmp_path):
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "payload_download", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z", "payload_sha256": "abc123"},
        {"action": "disconnect", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    ph = PayloadHandler(output_dir=str(tmp_path))
    payloads = ph.extract_payloads(sessions)
    ledger_path = ph.write_hash_ledger(payloads)
    assert os.path.exists(ledger_path)
    with open(ledger_path) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["payload_sha256"] == "abc123"
