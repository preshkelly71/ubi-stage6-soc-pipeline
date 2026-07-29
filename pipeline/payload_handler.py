"""
Payload Handler: Extracts payload hashes and metadata safely (no execution).

Never opens, runs, or executes captured payloads. Only records hashes and metadata.
"""
import csv
import os
from typing import List, Dict, Any


class PayloadHandler:
    """Handles payload extraction, hashing, and quarantine metadata."""

    def __init__(self, output_dir: str = "analysis-pipeline"):
        self.output_dir = output_dir

    def extract_payloads(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract payload metadata from sessions. Never executes payloads.
        Returns a list of payload records for the hash ledger.
        """
        payloads = []
        seen_hashes = set()

        for session in sessions:
            for event_id in session.get("event_ids", []):
                # We need to go back to the raw events — but we store payload info
                # in the session already. Let's extract from session metadata.
                pass

            # Extract from session-level payload hashes
            for payload_hash in session.get("payload_hashes", []):
                if payload_hash and payload_hash not in seen_hashes:
                    seen_hashes.add(payload_hash)
                    payloads.append({
                        "payload_sha256": payload_hash,
                        "source_ip": session["source_ip"],
                        "protocol": session["protocol"],
                        "session_id": session["session_id"],
                        "first_seen": session["start_time"],
                        "quarantine_status": "hashed_only",
                        "executed": False,
                        "bytes": None,  # Would be extracted from raw event if available
                    })

        return payloads

    def write_hash_ledger(self, payloads: List[Dict[str, Any]],
                          filename: str = "hash-ledger.csv") -> str:
        """Write payload hash ledger to CSV."""
        filepath = os.path.join(self.output_dir, filename)
        fieldnames = [
            "payload_sha256", "source_ip", "protocol", "session_id",
            "first_seen", "quarantine_status", "executed", "bytes"
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for payload in payloads:
                writer.writerow(payload)

        return filepath
