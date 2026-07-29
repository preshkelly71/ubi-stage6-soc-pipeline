"""Base adapter interface and schema detection for honeypot event normalization."""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseAdapter(ABC):
    """Abstract base class for honeypot schema adapters."""

    @abstractmethod
    def parse(self, event: Dict[str, Any], source_file: str, row_number: int) -> Dict[str, Any]:
        """Parse raw event dict into a canonical event representation."""
        pass


def detect_schema_version(event: Dict[str, Any]) -> str:
    """
    Detect schema version based on connection_id format.
    - Schema v1: 'conn-xxx'
    - Schema v2: 'S-ed7d82-xxx'
    Also checks schema_version field if present.
    """
    # Check explicit schema_version field
    sv = str(event.get("schema_version", ""))
    if sv == "1":
        return "v1"
    elif sv == "2":
        return "v2"

    # Fallback: detect from connection_id prefix
    conn_id = str(event.get("connection_id", ""))
    if conn_id.startswith("conn-"):
        return "v1"
    elif conn_id.startswith("S-"):
        return "v2"

    return "unknown"


def build_canonical_event(
    event_id: str,
    sensor_time: str,
    protocol: str,
    source_ip: str,
    source_port: Optional[int],
    destination_port: Optional[int],
    connection_id: str,
    action: str,
    username: Optional[str] = None,
    credential_fingerprint: Optional[str] = None,
    command: Optional[str] = None,
    payload_sha256: Optional[str] = None,
    bytes_count: Optional[int] = None,
    marker: Optional[str] = None,
    schema_version: str = "unknown",
    source_file: str = "",
    row_number: int = 0,
) -> Dict[str, Any]:
    """Constructs the canonical event dictionary."""
    return {
        "event_id": event_id,
        "sensor_time": sensor_time,
        "protocol": protocol,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "connection_id": connection_id,
        "action": action,
        "username": username,
        "credential_fingerprint": credential_fingerprint,
        "command": command,
        "payload_sha256": payload_sha256,
        "bytes": bytes_count,
        "marker": marker,
        "schema_version": schema_version,
        "source_file": source_file,
        "row_number": row_number,
    }
