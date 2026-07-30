# Decision Log

| ID | UTC time | Decision | Evidence used | Alternatives rejected | Assumption | Owner | Review trigger |
|---|---|---|---|---|---|---|---|
| D-001 | 2026-07-29T12:00:00Z | Group events by connection_id for sessionization | replay-interface.json specifies connection_id as session key | Grouping by source_ip alone (would merge reconnects) | connection_id uniquely identifies one TCP connection | UBI-2026-0155 | If fixture tests fail |
| D-002 | 2026-07-29T12:00:00Z | Use uuid5 with fixed namespace for STIX UUIDs | Reproducibility requirement in brief | uuid4 (random, fails determinism check) | Same input must produce byte-identical output | UBI-2026-0155 | If output hashes differ between runs |
| D-003 | 2026-07-29T12:00:00Z | Quarantine invalid events, do not crash pipeline | 0 quarantined events confirms data quality | Raise exception on first error | All 250K events are structurally valid | UBI-2026-0155 | If quarantine count rises above 0 |
| D-004 | 2026-07-29T12:00:00Z | Classify session as full_attack only if payload_download present | Project brief defines attack success by payload delivery | Classify by auth_success alone | payload_download = completed attack intent | UBI-2026-0155 | If session count changes |
| D-005 | 2026-07-29T12:00:00Z | Treat reputation as context not attribution | Project brief explicit: enrich but do not attribute | Block IPs based on reputation score alone | Honeypot data is self-contained evidence | UBI-2026-0155 | Never, brief is explicit |

Every consequential judgment belongs here. A report conclusion without a
decision trail may be treated as unsupported during defense.
