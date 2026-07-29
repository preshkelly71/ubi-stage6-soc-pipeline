"""Malformed input tests — quarantine handling for corrupt/missing/empty data."""
import json
import os
import sys
import tempfile
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.normalizer import Normalizer


@pytest.fixture
def normalizer(tmp_path):
    return Normalizer(quarantine_file=str(tmp_path / "quarantine.jsonl"))


def write_jsonl(tmp_path, lines):
    f = tmp_path / "test.jsonl"
    with open(f, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    return str(f)


def test_corrupt_json(normalizer, tmp_path):
    """Corrupt JSON is quarantined."""
    f = write_jsonl(tmp_path, ['{bad json}', '{"event_id":"e1","sensor_time":"2026-01-01T00:00:00Z","protocol":"ssh","source_ip":"1.2.3.4","connection_id":"conn-1","action":"connect","schema_version":"1"}'])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 1
    assert quarantined == 1


def test_missing_required_fields(normalizer, tmp_path):
    """Events missing required fields are quarantined."""
    f = write_jsonl(tmp_path, ['{"event_id":"e1","protocol":"ssh","connection_id":"conn-1","action":"connect"}'])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 0
    assert quarantined == 1


def test_unknown_schema(normalizer, tmp_path):
    """Unknown schema version is quarantined."""
    f = write_jsonl(tmp_path, ['{"event_id":"e1","sensor_time":"2026-01-01T00:00:00Z","protocol":"ssh","source_ip":"1.2.3.4","connection_id":"X-123","action":"connect"}'])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 0
    assert quarantined == 1


def test_empty_file(normalizer, tmp_path):
    """Empty file produces zero events."""
    f = write_jsonl(tmp_path, [])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 0
    assert quarantined == 0


def test_empty_lines(normalizer, tmp_path):
    """Empty lines are skipped."""
    f = write_jsonl(tmp_path, ['', '  ', '{"event_id":"e1","sensor_time":"2026-01-01T00:00:00Z","protocol":"ssh","source_ip":"1.2.3.4","connection_id":"conn-1","action":"connect","schema_version":"1"}'])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 1
    assert quarantined == 0


def test_nonexistent_file(normalizer):
    """Nonexistent file returns empty."""
    events, valid, quarantined = normalizer.normalize_file("/nonexistent/path.jsonl")
    assert valid == 0
    assert quarantined == 0


def test_unicode_content(normalizer, tmp_path):
    """Unicode content in valid events is handled."""
    event = {"event_id": "e1", "sensor_time": "2026-01-01T00:00:00Z", "protocol": "ssh", "source_ip": "1.2.3.4", "connection_id": "conn-1", "action": "connect", "schema_version": "1", "username": "测试用户"}
    f = write_jsonl(tmp_path, [json.dumps(event, ensure_ascii=False)])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 1


def test_null_values(normalizer, tmp_path):
    """Null values in optional fields are accepted."""
    event = {"event_id": "e1", "sensor_time": "2026-01-01T00:00:00Z", "protocol": "ssh", "source_ip": "1.2.3.4", "connection_id": "conn-1", "action": "connect", "schema_version": "1", "username": None}
    f = write_jsonl(tmp_path, [json.dumps(event)])
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 1


def test_mixed_valid_and_invalid(normalizer, tmp_path):
    """Mixed valid and invalid records are split correctly."""
    lines = [
        '{"event_id":"e1","sensor_time":"2026-01-01T00:00:00Z","protocol":"ssh","source_ip":"1.2.3.4","connection_id":"conn-1","action":"connect","schema_version":"1"}',
        '{corrupt}',
        '{"event_id":"e2","sensor_time":"2026-01-01T00:00:01Z","protocol":"ssh","source_ip":"1.2.3.4","connection_id":"S-ed7d82-0000002","action":"auth_fail","schema_version":"2"}',
        '{"event_id":"","sensor_time":"","protocol":"","source_ip":"","connection_id":"","action":""}',
    ]
    f = write_jsonl(tmp_path, lines)
    events, valid, quarantined = normalizer.normalize_file(f)
    assert valid == 2
    assert quarantined == 2
