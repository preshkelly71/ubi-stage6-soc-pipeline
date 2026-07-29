"""
Clusterer: Groups sessions by shared infrastructure (IPs, credentials, payloads).

Three clustering dimensions:
1. By source_ip: sessions from the same IP
2. By credential_fingerprint: sessions using the same credential
3. By payload_sha256: sessions downloading the same malware
"""
from typing import List, Dict, Any
from collections import defaultdict


class Clusterer:
    """Clusters sessions by shared infrastructure indicators."""

    def cluster(self, sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Cluster sessions by source IP, credential fingerprint, and payload hash.
        Returns a dict with 'by_ip', 'by_credential', 'by_payload' clusters.
        """
        return {
            "by_ip": self._cluster_by_ip(sessions),
            "by_credential": self._cluster_by_credential(sessions),
            "by_payload": self._cluster_by_payload(sessions),
            "summary": self._build_summary(sessions),
        }

    def _cluster_by_ip(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group sessions by source IP address."""
        groups = defaultdict(list)
        for s in sessions:
            groups[s["source_ip"]].append(s["session_id"])

        clusters = []
        for ip, session_ids in sorted(groups.items()):
            # Get representative session for metadata
            rep = next(s for s in sessions if s["source_ip"] == ip)
            clusters.append({
                "cluster_type": "source_ip",
                "cluster_key": ip,
                "cluster_id": f"IP-{ip}",
                "session_count": len(session_ids),
                "session_ids": sorted(session_ids),
                "protocols": list(set(s["protocol"] for s in sessions if s["source_ip"] == ip)),
                "has_successful": any(
                    s["has_auth_success"] for s in sessions if s["source_ip"] == ip
                ),
                "has_payload": any(
                    s["has_payload_download"] for s in sessions if s["source_ip"] == ip
                ),
            })
        return clusters

    def _cluster_by_credential(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group sessions by credential fingerprint."""
        cred_sessions = defaultdict(list)
        for s in sessions:
            for cred in s.get("credentials_used", []):
                cred_sessions[cred].append(s["session_id"])

        clusters = []
        for cred, session_ids in sorted(cred_sessions.items()):
            # Find sessions using this credential
            matching = [s for s in sessions if cred in s.get("credentials_used", [])]
            clusters.append({
                "cluster_type": "credential",
                "cluster_key": cred,
                "cluster_id": f"CRED-{cred[:12]}",
                "session_count": len(session_ids),
                "session_ids": sorted(session_ids),
                "source_ips": sorted(set(s["source_ip"] for s in matching)),
                "protocols": sorted(set(s["protocol"] for s in matching)),
            })
        return clusters

    def _cluster_by_payload(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group sessions by payload SHA-256 hash."""
        payload_sessions = defaultdict(list)
        for s in sessions:
            for h in s.get("payload_hashes", []):
                payload_sessions[h].append(s["session_id"])

        clusters = []
        for payload_hash, session_ids in sorted(payload_sessions.items()):
            matching = [s for s in sessions if payload_hash in s.get("payload_hashes", [])]
            clusters.append({
                "cluster_type": "payload",
                "cluster_key": payload_hash,
                "cluster_id": f"PAYLOAD-{payload_hash[:12]}",
                "session_count": len(session_ids),
                "session_ids": sorted(session_ids),
                "source_ips": sorted(set(s["source_ip"] for s in matching)),
                "protocols": sorted(set(s["protocol"] for s in matching)),
            })
        return clusters

    def _build_summary(self, sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build cluster summary statistics."""
        unique_ips = len(set(s["source_ip"] for s in sessions))
        unique_creds = set()
        unique_payloads = set()
        for s in sessions:
            unique_creds.update(s.get("credentials_used", []))
            unique_payloads.update(s.get("payload_hashes", []))

        return {
            "total_sessions": len(sessions),
            "unique_source_ips": unique_ips,
            "unique_credentials": len(unique_creds),
            "unique_payload_hashes": len(unique_payloads),
            "full_attack_sessions": sum(1 for s in sessions if s["session_type"] == "full_attack"),
            "successful_login_sessions": sum(1 for s in sessions if s["session_type"] == "successful_login"),
            "failed_login_sessions": sum(1 for s in sessions if s["session_type"] == "failed_login"),
        }
