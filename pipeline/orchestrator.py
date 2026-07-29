"""
Orchestrator: Runs the full pipeline from raw replay to all deliverables.
"""
import json
import os
import time
import hashlib
import pandas as pd
from typing import Dict, Any
from pipeline.normalizer import Normalizer
from pipeline.sessionizer import Sessionizer
from pipeline.clusterer import Clusterer
from pipeline.payload_handler import PayloadHandler
from pipeline.stix_generator import STIXGenerator
from pipeline.detection_writer import DetectionWriter


class Orchestrator:
    """Runs the full analysis pipeline end-to-end."""

    def __init__(self, replay_path: str = "replay/raw/honeypot-replay.jsonl"):
        self.replay_path = replay_path
        self.stats = {}

    def run(self) -> Dict[str, Any]:
        """Run the full pipeline. Returns statistics."""
        total_start = time.time()

        # Phase 1: Normalize
        print("[1/7] Normalizing raw events...")
        start = time.time()
        normalizer = Normalizer(quarantine_file="quarantine/quarantined.jsonl")
        events, valid_count, quarantined_count = normalizer.normalize_file(self.replay_path)
        self.stats["normalization"] = {
            "valid_events": valid_count,
            "quarantined": quarantined_count,
            "time_seconds": round(time.time() - start, 2),
        }
        print(f"  {valid_count} valid, {quarantined_count} quarantined")

        # Phase 2: Sessionize
        print("[2/7] Sessionizing events...")
        start = time.time()
        sessionizer = Sessionizer()
        sessions = sessionizer.sessionize(events)
        self.stats["sessionization"] = {
            "total_sessions": len(sessions),
            "time_seconds": round(time.time() - start, 2),
        }
        print(f"  {len(sessions)} sessions created")

        # Free events memory — convert sessions to DataFrame
        events_df = pd.DataFrame(events)
        del events

        # Write sessions to Parquet
        sessions_df = pd.DataFrame(sessions)
        sessions_path = os.path.join("analysis-pipeline", "sessions.parquet")
        sessions_df.to_parquet(sessions_path)
        print(f"  Sessions written to {sessions_path}")

        # Phase 3: Cluster
        print("[3/7] Clustering sessions...")
        start = time.time()
        clusterer = Clusterer()
        clusters = clusterer.cluster(sessions)
        self.stats["clustering"] = {
            "ip_clusters": len(clusters["by_ip"]),
            "credential_clusters": len(clusters["by_credential"]),
            "payload_clusters": len(clusters["by_payload"]),
            "time_seconds": round(time.time() - start, 2),
        }
        clusters_path = os.path.join("analysis-pipeline", "clusters.json")
        with open(clusters_path, "w") as f:
            json.dump(clusters, f, indent=2, sort_keys=True)
        print(f"  {len(clusters['by_ip'])} IP, {len(clusters['by_credential'])} cred, {len(clusters['by_payload'])} payload clusters")

        # Phase 4: Payload handling
        print("[4/7] Extracting payload metadata...")
        start = time.time()
        payload_handler = PayloadHandler()
        payloads = payload_handler.extract_payloads(sessions)
        hash_ledger_path = payload_handler.write_hash_ledger(payloads)
        self.stats["payload_handling"] = {
            "unique_payloads": len(payloads),
            "time_seconds": round(time.time() - start, 2),
        }
        print(f"  {len(payloads)} unique payloads, hash ledger at {hash_ledger_path}")

        # Phase 5: STIX generation
        print("[5/7] Generating STIX 2.1 bundle...")
        start = time.time()
        stix_gen = STIXGenerator()
        stix_result = stix_gen.generate_bundle(sessions, clusters)
        stix_path = stix_gen.write_bundle(stix_result)
        self.stats["stix_generation"] = {
            "total_objects": stix_result["stats"]["total_objects"],
            "indicators": stix_result["stats"]["indicators"],
            "relationships": stix_result["stats"]["relationships"],
            "time_seconds": round(time.time() - start, 2),
        }
        print(f"  {stix_result['stats']['total_objects']} STIX objects, bundle at {stix_path}")

        # Phase 6: Detection rules
        print("[6/7] Writing detection rules...")
        start = time.time()
        detection_writer = DetectionWriter()
        detection_result = detection_writer.write_detections(sessions)
        self.stats["detection_writing"] = {
            "sigma_rules": detection_result["sigma_count"],
            "suricata_rules": detection_result["suricata_count"],
            "time_seconds": round(time.time() - start, 2),
        }
        print(f"  {detection_result['sigma_count']} Sigma, {detection_result['suricata_count']} Suricata rules")

        # Phase 7: Output hash ledger
        print("[7/7] Computing output hashes...")
        output_hashes = {}
        for output_file in [
            "analysis-pipeline/sessions.parquet",
            "analysis-pipeline/clusters.json",
            "analysis-pipeline/stix-bundle.json",
            "analysis-pipeline/hash-ledger.csv",
        ]:
            if os.path.exists(output_file):
                with open(output_file, "rb") as f:
                    output_hashes[output_file] = hashlib.sha256(f.read()).hexdigest()

        self.stats["output_hashes"] = output_hashes
        self.stats["total_time_seconds"] = round(time.time() - total_start, 2)

        print(f"\nPipeline complete in {self.stats['total_time_seconds']}s")
        return self.stats
