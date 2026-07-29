"""Clusterer tests."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.clusterer import Clusterer
from pipeline.sessionizer import Sessionizer


def test_cluster_by_ip():
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "disconnect", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "connect", "event_id": "e3", "protocol": "ssh", "src": "5.6.7.8", "time": "2026-01-01T00:00:02Z"},
        {"action": "disconnect", "event_id": "e4", "protocol": "ssh", "src": "5.6.7.8", "time": "2026-01-01T00:00:03Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    c = Clusterer()
    clusters = c.cluster(sessions)
    assert len(clusters["by_ip"]) == 2


def test_cluster_by_credential():
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_fail", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z", "credential_fingerprint": "abc123"},
        {"action": "disconnect", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    c = Clusterer()
    clusters = c.cluster(sessions)
    assert len(clusters["by_credential"]) == 1
    assert clusters["by_credential"][0]["cluster_key"] == "abc123"


def test_cluster_summary():
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "disconnect", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    c = Clusterer()
    clusters = c.cluster(sessions)
    assert clusters["summary"]["total_sessions"] == 1
    assert clusters["summary"]["unique_source_ips"] == 1
