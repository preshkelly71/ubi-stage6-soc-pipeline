"""
Sessionizer edge case tests.
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.sessionizer import Sessionizer


def test_empty_input():
    """Empty input produces zero sessions."""
    s = Sessionizer()
    assert s.sessionize([]) == []


def test_single_connect_no_disconnect():
    """A connect without disconnect is still a valid session."""
    events = [{"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"}]
    s = Sessionizer()
    sessions = s.sessionize(events)
    assert len(sessions) == 1
    assert sessions[0]["event_count"] == 1


def test_reconnect_produces_two_sessions():
    """A reconnect (connect, disconnect, connect, disconnect) produces two sessions."""
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_fail", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "disconnect", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z"},
        {"action": "connect", "event_id": "e4", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:03Z"},
        {"action": "auth_success", "event_id": "e5", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:04Z"},
        {"action": "disconnect", "event_id": "e6", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:05Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    assert len(sessions) == 2
    assert sessions[0]["event_count"] == 3
    assert sessions[1]["event_count"] == 3
    assert not sessions[0]["has_auth_success"]
    assert sessions[1]["has_auth_success"]


def test_shuffled_events_sorted_by_time():
    """Shuffled events are sorted by time within sessions."""
    events = [
        {"action": "disconnect", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z"},
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_fail", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    assert sessions[0]["event_ids"] == ["e1", "e2", "e3"]


def test_connection_id_grouping():
    """Replay events are grouped by connection_id."""
    events = [
        {"event_id": "S-ed7d82-1-1", "sensor_time": "2026-01-01T00:00:01Z", "protocol": "ssh", "source_ip": "1.2.3.4", "connection_id": "conn-aaa", "action": "connect"},
        {"event_id": "S-ed7d82-1-2", "sensor_time": "2026-01-01T00:00:02Z", "protocol": "ssh", "source_ip": "1.2.3.4", "connection_id": "conn-aaa", "action": "auth_fail"},
        {"event_id": "S-ed7d82-2-1", "sensor_time": "2026-01-01T00:00:01Z", "protocol": "ssh", "source_ip": "5.6.7.8", "connection_id": "conn-bbb", "action": "connect"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    assert len(sessions) == 2
    assert sessions[0]["connection_id"] == "conn-aaa"
    assert sessions[1]["connection_id"] == "conn-bbb"


def test_full_attack_session_type():
    """A session with payload_download is classified as full_attack."""
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_success", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "payload_download", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z", "payload_sha256": "abc123"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    assert sessions[0]["session_type"] == "full_attack"
    assert sessions[0]["has_payload_download"]


def test_clean_state_no_residual():
    """New Sessionizer instance has no residual state."""
    events1 = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "disconnect", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
    ]
    s1 = Sessionizer()
    s1.sessionize(events1)
    assert s1.get_session_count() == 1

    s2 = Sessionizer()
    assert s2.get_session_count() == 0
    s2.sessionize(events1)
    assert s2.get_session_count() == 1
