"""
STIX 2.1 Generator: Creates deterministic STIX bundles from sessions and clusters.

Uses uuid5 (SHA-1 based) for deterministic UUIDs and FIXED timestamps
so the same input always produces byte-identical output.
"""
import json
import os
import uuid
from typing import List, Dict, Any
from stix2 import (
    Bundle, Indicator, Relationship,
    AttackPattern, Identity, Malware
)

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# Fixed timestamp for all STIX objects — ensures determinism
FIXED_TIME = "2026-07-01T00:00:00Z"


def deterministic_uuid(value: str) -> str:
    """Generate a deterministic UUID from a string value using uuid5."""
    return str(uuid.uuid5(NAMESPACE, value))


class STIXGenerator:
    """Generates STIX 2.1 bundles from sessions and clusters."""

    def __init__(self):
        self.identity = Identity(
            id="identity--" + deterministic_uuid("ubi-soc-stage6"),
            name="UBI SOC Stage 6 Analysis Pipeline",
            identity_class="system",
            created=FIXED_TIME,
            modified=FIXED_TIME,
        )

    def generate_bundle(self, sessions: List[Dict[str, Any]],
                        clusters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a STIX 2.1 bundle from sessions and clusters."""
        objects = [self.identity]
        indicators_created = 0
        relationships_created = 0

        full_attack_sessions = [
            s for s in sessions if s["session_type"] == "full_attack"
        ]

        # Sort sessions for deterministic order
        full_attack_sessions.sort(key=lambda s: (s["source_ip"], s["session_id"]))

        for session in full_attack_sessions:
            src_ip = session["source_ip"]
            proto = session["protocol"]
            start_time = session["start_time"]

            ip_id = "indicator--" + deterministic_uuid("ip-" + src_ip)
            ip_indicator = Indicator(
                id=ip_id,
                name="Malicious source IP: " + src_ip,
                pattern="[ipv4-addr:value = '" + src_ip + "']",
                pattern_type="stix",
                valid_from=start_time,
                labels=["malicious-activity", "honeypot"],
                description="Source IP observed in full attack session on " + proto,
                created_by_ref=self.identity.id,
                created=FIXED_TIME,
                modified=FIXED_TIME,
            )
            objects.append(ip_indicator)
            indicators_created += 1

            for cred in sorted(session.get("credentials_used", [])):
                cred_id = "indicator--" + deterministic_uuid("cred-" + cred)
                cred_indicator = Indicator(
                    id=cred_id,
                    name="Compromised credential: " + cred[:12],
                    pattern="[x-ubi-credential:credential_fingerprint = '" + cred + "']",
                    pattern_type="stix",
                    valid_from=start_time,
                    labels=["compromised", "honeypot"],
                    description="Credential fingerprint observed in successful attack",
                    created_by_ref=self.identity.id,
                    created=FIXED_TIME,
                    modified=FIXED_TIME,
                )
                objects.append(cred_indicator)
                indicators_created += 1

                rel_id = "relationship--" + deterministic_uuid("rel-" + ip_id + "-" + cred_id)
                rel = Relationship(
                    id=rel_id,
                    relationship_type="uses",
                    source_ref=ip_id,
                    target_ref=cred_id,
                    description="IP " + src_ip + " used credential " + cred[:12],
                    created=FIXED_TIME,
                    modified=FIXED_TIME,
                )
                objects.append(rel)
                relationships_created += 1

            for payload_hash in sorted(session.get("payload_hashes", [])):
                malware_id = "malware--" + deterministic_uuid("payload-" + payload_hash)
                malware = Malware(
                    id=malware_id,
                    name="Malware sample " + payload_hash[:12],
                    is_family=False,
                    malware_types=["unknown"],
                    created=FIXED_TIME,
                    modified=FIXED_TIME,
                )
                objects.append(malware)

                rel_id = "relationship--" + deterministic_uuid("rel-" + ip_id + "-" + malware_id)
                rel = Relationship(
                    id=rel_id,
                    relationship_type="delivers",
                    source_ref=ip_id,
                    target_ref=malware_id,
                    description="IP " + src_ip + " delivered malware " + payload_hash[:12],
                    created=FIXED_TIME,
                    modified=FIXED_TIME,
                )
                objects.append(rel)
                relationships_created += 1

        for technique_id, technique_name in [
            ("T1110", "Brute Force"),
            ("T1059", "Command and Scripting Interpreter"),
            ("T1105", "Ingress Tool Transfer"),
        ]:
            ap = AttackPattern(
                id="attack-pattern--" + deterministic_uuid("mitre-" + technique_id),
                name=technique_name,
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": "https://attack.mitre.org/techniques/" + technique_id,
                }],
                created=FIXED_TIME,
                modified=FIXED_TIME,
            )
            objects.append(ap)

        bundle = Bundle(objects=objects, allow_custom=True)
        bundle_dict = json.loads(bundle.serialize())
        bundle_dict["id"] = "bundle--" + deterministic_uuid("ubi-soc-stage6-bundle-v2")

        return {
            "bundle": bundle_dict,
            "stats": {
                "total_objects": len(objects),
                "indicators": indicators_created,
                "relationships": relationships_created,
                "attack_patterns": 3,
            },
        }

    def write_bundle(self, stix_result: Dict[str, Any],
                     filename: str = "stix-bundle.json") -> str:
        """Write STIX bundle to file."""
        filepath = os.path.join("analysis-pipeline", filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(stix_result["bundle"], f, indent=2, sort_keys=True)
        return filepath
