"""
Event normalizer for processing raw honeypot logs into canonical schema.
Streams the file line by line to keep memory low.
"""
import json
import os
from typing import List, Dict, Any, Tuple
from pipeline.adapters.base import detect_schema_version
from pipeline.adapters.schema_v1 import SchemaV1Adapter
from pipeline.adapters.schema_v2 import SchemaV2Adapter

REQUIRED_FIELDS = ["event_id", "sensor_time", "protocol", "source_ip", "connection_id", "action"]


class Normalizer:
    """Normalizes raw log files into canonical events or routes bad records to quarantine."""

    def __init__(self, quarantine_file: str = "quarantine/quarantined.jsonl"):
        self.quarantine_file = quarantine_file
        self.adapters = {"v1": SchemaV1Adapter(), "v2": SchemaV2Adapter()}
        os.makedirs(os.path.dirname(self.quarantine_file), exist_ok=True)

    def normalize_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], int, int]:
        """
        Process a single JSONL file.
        Returns: (valid_events, valid_count, quarantined_count)
        """
        valid_events = []
        valid_count = 0
        quarantined_count = 0

        if not os.path.exists(file_path):
            return valid_events, valid_count, quarantined_count

        # Open quarantine file ONCE for the whole run
        quarantine_handle = open(self.quarantine_file, "a", encoding="utf-8")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for row_number, line in enumerate(f, start=1):
                    line_str = line.strip()
                    if not line_str:
                        continue

                    # 1. Try parsing JSON
                    try:
                        raw_event = json.loads(line_str)
                    except json.JSONDecodeError as err:
                        self._quarantine(quarantine_handle, raw_data=line_str,
                                         reason=f"JSON Decode Error: {str(err)}",
                                         source_file=file_path, row_number=row_number)
                        quarantined_count += 1
                        continue

                    # 2. Detect Schema
                    schema_version = detect_schema_version(raw_event)
                    if schema_version not in self.adapters:
                        self._quarantine(quarantine_handle, raw_data=raw_event,
                                         reason=f"Unknown or unsupported schema version ('{schema_version}')",
                                         source_file=file_path, row_number=row_number)
                        quarantined_count += 1
                        continue

                    # 3. Parse via Adapter
                    adapter = self.adapters[schema_version]
                    canonical_event = adapter.parse(raw_event, source_file=file_path, row_number=row_number)

                    # 4. Validate Mandatory Fields
                    missing_fields = [f for f in REQUIRED_FIELDS if not canonical_event.get(f)]
                    if missing_fields:
                        self._quarantine(quarantine_handle, raw_data=raw_event,
                                         reason=f"Missing required fields: {', '.join(missing_fields)}",
                                         source_file=file_path, row_number=row_number)
                        quarantined_count += 1
                        continue

                    valid_events.append(canonical_event)
                    valid_count += 1
        finally:
            quarantine_handle.close()

        return valid_events, valid_count, quarantined_count

    def _quarantine(self, handle, raw_data: Any, reason: str, source_file: str, row_number: int):
        """Append bad or unparseable records to quarantine file."""
        record = {
            "source_file": source_file,
            "row_number": row_number,
            "reason": reason,
            "raw_record": raw_data,
        }
        handle.write(json.dumps(record) + "\n")
