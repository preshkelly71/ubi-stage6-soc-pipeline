"""Detection writer tests."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.sessionizer import Sessionizer
from pipeline.detection_writer import DetectionWriter


def test_sigma_rules_written(tmp_path):
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "disconnect", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    dw = DetectionWriter()
    sigma_files = dw.write_sigma_rules(sessions, output_dir=str(tmp_path / "sigma"))
    assert len(sigma_files) == 3
    for f in sigma_files:
        assert os.path.exists(f)
        content = open(f).read()
        assert "title:" in content
        assert "detection:" in content


def test_suricata_rules_written(tmp_path):
    events = [
        {"action": "connect", "event_id": "e1", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:00Z"},
        {"action": "auth_success", "event_id": "e2", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:01Z"},
        {"action": "payload_download", "event_id": "e3", "protocol": "ssh", "src": "1.2.3.4", "time": "2026-01-01T00:00:02Z", "payload_sha256": "abc"},
    ]
    s = Sessionizer()
    sessions = s.sessionize(events)
    dw = DetectionWriter()
    suricata_path = dw.write_suricata_rules(sessions, output_dir=str(tmp_path))
    assert os.path.exists(suricata_path)
    content = open(suricata_path).read()
    assert "alert" in content
    assert "1.2.3.4" in content
