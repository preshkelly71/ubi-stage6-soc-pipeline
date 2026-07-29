"""
Public fixture acceptance suite — 16 cases, each tested individually.
"""
import json
import os
import pytest
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.sessionizer import Sessionizer

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "public-fixtures.json")


def load_fixtures():
    with open(FIXTURES_PATH) as f:
        data = json.load(f)
    return data["fixtures"]


FIXTURES = load_fixtures()


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f["case_id"] for f in FIXTURES])
def test_fixture_session_count(fixture):
    """Each fixture produces the expected number of sessions."""
    s = Sessionizer()
    sessions = s.sessionize(fixture["input"])
    assert len(sessions) == fixture["expected"]["session_count"], \
        f"{fixture['case_id']}: expected {fixture['expected']['session_count']} sessions, got {len(sessions)}"


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f["case_id"] for f in FIXTURES])
def test_fixture_event_order(fixture):
    """Each fixture produces events in the expected order."""
    s = Sessionizer()
    sessions = s.sessionize(fixture["input"])
    actual_order = s.get_ordered_event_ids()
    assert actual_order == fixture["expected"]["ordered_event_ids"], \
        f"{fixture['case_id']}: expected {fixture['expected']['ordered_event_ids']}, got {actual_order}"


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f["case_id"] for f in FIXTURES])
def test_fixture_protocol(fixture):
    """Each fixture has the correct protocol."""
    s = Sessionizer()
    sessions = s.sessionize(fixture["input"])
    for sess in sessions:
        assert sess["protocol"] == fixture["expected"]["protocol"], \
            f"{fixture['case_id']}: expected {fixture['expected']['protocol']}, got {sess['protocol']}"
