# UBI Stage 6 Project 2: Deception Sensor and Analysis Pipeline

## Overview

This project implements a production-style deception sensor (honeypot) boundary
and analysis pipeline for the Ubuntu Bridge Initiative (UBI) Stage 6 Advanced
Project 2. The pipeline ingests sealed T-Pot replay data, normalizes it through
schema adapters, sessionizes reordered events, clusters attack infrastructure,
extracts payload hashes safely (without execution), generates STIX 2.1 threat
intelligence bundles, and emits Sigma + Suricata detection rules.

## Assignment

- Intern code: UBI-2026-0155
- Variant: V2
- Evidence marker: UBI-A6-679461BECC22
- Deadline: August 4, 2026, 18:00 WAT

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run the full pipeline
make analyze

# Or run directly
python -m pipeline.orchestrator
```

## Pipeline architecture

1. **Normalizer** — Reads JSONL, detects schema (v1/v2), routes to adapters, quarantines bad records
2. **Sessionizer** — Groups events into sessions (by connection_id for replay, by src+protocol for fixtures)
3. **Clusterer** — Groups sessions by source IP, credential fingerprint, and payload hash
4. **Payload Handler** — Extracts payload hashes without execution, writes hash-ledger.csv
5. **STIX Generator** — Creates deterministic STIX 2.1 bundle with indicators and relationships
6. **Detection Writer** — Generates Sigma rules and Suricata rules from detected threats
7. **Orchestrator** — Ties everything together, runs end-to-end

## Outputs

- analysis-pipeline/sessions.parquet — 125,030 sessions
- analysis-pipeline/clusters.json — 252 IP, 31 credential, 4 payload clusters
- analysis-pipeline/stix-bundle.json — 1,469 STIX objects
- analysis-pipeline/hash-ledger.csv — 4 unique payloads
- analysis-pipeline/detections/ — 3 Sigma + 293 Suricata rules
- sensor-infrastructure/isolation-results.json — 8 isolation tests

## Determinism

All outputs are deterministic. Running the pipeline twice produces identical
SHA-256 hashes. STIX UUIDs are generated using uuid5 (SHA-1 based) with a fixed
namespace. STIX object timestamps use a fixed reference time.

## Testing

77 tests across 7 test files:
- test_fixtures.py: 48 tests (16 fixtures x 3 assertions each)
- test_sessionizer.py: 7 edge case tests
- test_clusterer.py: 3 tests
- test_payload_handler.py: 3 tests
- test_stix.py: 5 tests (including determinism)
- test_detections.py: 2 tests
- test_malformed.py: 9 tests
