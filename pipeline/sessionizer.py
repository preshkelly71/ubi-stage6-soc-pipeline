"""
Sessionizer: Groups raw honeypot events into coherent attack sessions.

Two modes:
1. Replay mode (events have connection_id): group by connection_id, sort by sensor_time
2. Fixture mode (events have src/time): group by (src, protocol), split at disconnect boundaries

Session keys (from replay-interface.json): connection_id, source_ip, protocol, sensor_time
"""
from typing import List, Dict, Any
from collections import defaultdict


class Sessionizer:
    """Groups raw honeypot events into coherent attack sessions."""

    def __init__(self):
        self.sessions = []

    def sessionize(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Group events into sessions. Handles both replay and fixture formats.
        Returns a list of session dictionaries.
        """
        if not events:
            return []

        # Detect format: replay events have connection_id, fixtures use src/time
        has_connection_id = bool(events[0].get("connection_id"))

        if has_connection_id:
            return self._sessionize_by_connection_id(events)
        else:
            return self._sessionize_by_boundary(events)

    def _sessionize_by_connection_id(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Replay mode: Group by connection_id, sort by sensor_time.
        Uses all 4 session keys: connection_id, source_ip, protocol, sensor_time.
        """
        # Group by connection_id
        groups = defaultdict(list)
        for event in events:
            cid = event.get("connection_id", "")
            if cid:
                groups[cid].append(event)

        sessions = []
        for cid, group in groups.items():
            # Sort by sensor_time (also by event_id suffix as tiebreaker)
            group.sort(key=lambda e: (e.get("sensor_time", ""), e.get("event_id", "")))

            session = self._build_session(
                session_id=cid,
                events=group,
                connection_id=cid,
            )
            sessions.append(session)

        # Sort sessions by start time
        sessions.sort(key=lambda s: (s["start_time"], s["session_id"]))
        self.sessions = sessions
        return sessions

    def _sessionize_by_boundary(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fixture mode: Group by (src, protocol), split at disconnect boundaries.
        Handles reconnects: each connect...disconnect cycle is a separate session.
        """
        # Group by (src, protocol) — the fixture session keys
        groups = defaultdict(list)
        for event in events:
            src = event.get("src") or event.get("source_ip", "")
            proto = event.get("protocol", "")
            groups[(src, proto)].append(event)

        sessions = []
        for (src, proto), group in groups.items():
            # Sort by time
            group.sort(key=lambda e: e.get("time", e.get("sensor_time", "")))

            # Split at disconnect boundaries
            sub_sessions = self._split_at_boundaries(group)

            for idx, sub in enumerate(sub_sessions):
                session_id = f"{src}-{proto}-{idx + 1}"
                session = self._build_session(
                    session_id=session_id,
                    events=sub,
                    connection_id=None,
                )
                sessions.append(session)

        # Sort sessions by start time
        sessions.sort(key=lambda s: (s["start_time"], s["session_id"]))
        self.sessions = sessions
        return sessions

    def _split_at_boundaries(self, group: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """
        Split a group of events into sub-sessions at disconnect boundaries.
        A disconnect ends a session; the next event starts a new one.
        """
        sessions = []
        current = []

        for event in group:
            current.append(event)
            if event.get("action") == "disconnect":
                sessions.append(current)
                current = []

        # If there are leftover events (no trailing disconnect), add as incomplete session
        if current:
            sessions.append(current)

        return sessions

    def _build_session(self, session_id: str, events: List[Dict[str, Any]],
                       connection_id: str = None) -> Dict[str, Any]:
        """Build a session dictionary from a list of events."""
        event_ids = [e.get("event_id", "") for e in events]
        actions = [e.get("action", "") for e in events]

        # Extract source_ip and protocol from first event
        source_ip = events[0].get("source_ip") or events[0].get("src", "")
        protocol = events[0].get("protocol", "")

        # Times
        times = [e.get("sensor_time") or e.get("time", "") for e in events]
        start_time = min(times) if times else ""
        end_time = max(times) if times else ""

        # Session characteristics
        has_auth_success = "auth_success" in actions
        has_command = "command" in actions
        has_payload_download = "payload_download" in actions

        # Credentials
        credentials = [e.get("credential_fingerprint") for e in events
                       if e.get("credential_fingerprint")]
        usernames = [e.get("username") for e in events
                     if e.get("username")]

        # Payloads
        payload_hashes = [e.get("payload_sha256") for e in events
                          if e.get("payload_sha256")]

        # Commands
        commands = [e.get("command") for e in events
                    if e.get("command")]

        # Determine session type
        if has_payload_download:
            session_type = "full_attack"
        elif has_command:
            session_type = "successful_intrusion"
        elif has_auth_success:
            session_type = "successful_login"
        else:
            session_type = "failed_login"

        return {
            "session_id": session_id,
            "connection_id": connection_id,
            "source_ip": source_ip,
            "protocol": protocol,
            "start_time": start_time,
            "end_time": end_time,
            "event_count": len(events),
            "event_ids": event_ids,
            "actions": actions,
            "has_auth_success": has_auth_success,
            "has_command": has_command,
            "has_payload_download": has_payload_download,
            "credentials_used": list(set(credentials)),
            "usernames": list(set(usernames)),
            "payload_hashes": list(set(payload_hashes)),
            "commands_executed": list(set(commands)),
            "session_type": session_type,
        }

    def get_session_count(self) -> int:
        """Return the number of sessions."""
        return len(self.sessions)

    def get_ordered_event_ids(self) -> List[str]:
        """Return all event IDs in session order."""
        ids = []
        for session in self.sessions:
            ids.extend(session["event_ids"])
        return ids
