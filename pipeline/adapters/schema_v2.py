"""Schema Version 2 adapter (S- prefix connection IDs)."""
from typing import Dict, Any
from .base import BaseAdapter, build_canonical_event


class SchemaV2Adapter(BaseAdapter):
    """Adapter for Schema Version 2 raw events."""

    def parse(self, event: Dict[str, Any], source_file: str, row_number: int) -> Dict[str, Any]:
        return build_canonical_event(
            event_id=str(event.get("event_id", "")),
            sensor_time=str(event.get("sensor_time", "")),
            protocol=str(event.get("protocol", "")),
            source_ip=str(event.get("source_ip", "")),
            source_port=event.get("source_port"),
            destination_port=event.get("destination_port"),
            connection_id=str(event.get("connection_id", "")),
            action=str(event.get("action", "")),
            username=event.get("username"),
            credential_fingerprint=event.get("credential_fingerprint"),
            command=event.get("command"),
            payload_sha256=event.get("payload_sha256"),
            bytes_count=event.get("bytes"),
            marker=event.get("marker"),
            schema_version="v2",
            source_file=source_file,
            row_number=row_number,
        )
