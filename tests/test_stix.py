"""STIX generator tests — validates deterministic output and STIX 2.1 compliance."""
import json
import sys
import os
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.sessionizer import Sessionizer
from pipeline.stix_generator import STIXGenerator, deterministic_uuid


def test_deterministic_uuid():
    """Same input produces same UUID."""
    u1 = deterministic_uuid("test-value")
    u2 = deterministic_uuid("test-value")
    assert u1 == u2
    assert len(u1) == 36  # UUID format: 8-4-4-4-12


def test_stix_bundle_has_objects():
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_success", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "payload_download", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z", "payload_sha256": "abc123"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    gen = STIXGenerator()
    result = gen.generate_bundle(sessions, {})
    assert "bundle" in result
    assert "objects" in result["bundle"]
    assert len(result["bundle"]["objects"]) > 0
    assert result["stats"]["indicators"] > 0


def test_stix_bundle_type():
    """STIX bundle has the correct type field."""
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "disconnect", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    gen = STIXGenerator()
    result = gen.generate_bundle(sessions, {})
    assert result["bundle"]["type"] == "bundle"


def test_stix_deterministic_output():
    """Same input produces identical STIX bundle (deterministic)."""
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_success", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "payload_download", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z", "payload_sha256": "abc123"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)

    gen1 = STIXGenerator()
    r1 = gen1.generate_bundle(sessions, {})
    gen2 = STIXGenerator()
    r2 = gen2.generate_bundle(sessions, {})

    assert json.dumps(r1["bundle"], sort_keys=True) == json.dumps(r2["bundle"], sort_keys=True)


def test_stix_bundle_id_deterministic():
    """Bundle ID is the same across runs."""
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "disconnect", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)

    gen1 = STIXGenerator()
    r1 = gen1.generate_bundle(sessions, {})
    gen2 = STIXGenerator()
    r2 = gen2.generate_bundle(sessions, {})

    assert r1["bundle"]["id"] == r2["bundle"]["id"]
