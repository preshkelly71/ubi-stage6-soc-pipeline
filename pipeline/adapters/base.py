"""
Base adapter and schema detection logic for UBI Stage 6.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseAdapter(ABC):
    """Abstract adapter for converting raw events to canonical format."""

    @abstractmethod
    def parse(self, event: Dict[str, Any], source_file: str, row_number: int) -> Dict[str, Any]:
        """
        Parse a raw event and return a canonical event dictionary.

        Args:
            event: Raw event dict from JSONL.
            source_file: Path to the source file.
            row_number: 1-based line number in the source file.

        Returns:
            Canonical event dict (see build_canonical_event).
        """
        pass


def detect_schema_version(event: Dict[str, Any]) -> str:
    """
    Detect schema version from event.

    Priority:
        1. Check 'schema_version' field: "1" -> "v1", "2" -> "v2".
        2. Fallback: connection_id prefix: "conn-" -> "v1", "S-" -> "v2".
        3. Otherwise "unknown".

    Returns:
        "v1", "v2", or "unknown".
    """
    sv = str(event.get('schema_version', ''))
    if sv == '1':
        return 'v1'
    if sv == '2':
        return 'v2'

    conn_id = str(event.get('connection_id', ''))
    if conn_id.startswith('conn-'):
        return 'v1'
    if conn_id.startswith('S-'):
        return 'v2'

    return 'unknown'


def build_canonical_event(
    event_id: str,
    sensor_time: str,
    protocol: str,
    source_ip: str,
    source_port: int,
    destination_port: int,
    connection_id: str,
    action: str,
    username: Optional[str] = None,
    credential_fingerprint: Optional[str] = None,
    command: Optional[str] = None,
    payload_sha256: Optional[str] = None,
    bytes_count: Optional[int] = None,
    marker: Optional[str] = None,
    schema_version: str = 'unknown',
    source_file: str = '',
    row_number: int = 0
) -> Dict[str, Any]:
    """
    Build a canonical event dictionary with provenance.

    Returns:
        Dictionary with all required and optional fields.
    """
    return {
        'event_id': event_id,
        'sensor_time': sensor_time,
        'protocol': protocol,
        'source_ip': source_ip,
        'source_port': source_port,
        'destination_port': destination_port,
        'connection_id': connection_id,
        'action': action,
        'username': username,
        'credential_fingerprint': credential_fingerprint,
        'command': command,
        'payload_sha256': payload_sha256,
        'bytes': bytes_count,
        'marker': marker,
        'schema_version': schema_version,
        'source_file': source_file,
        'row_number': row_number,
    }
