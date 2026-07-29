# Honeypot Session Analysis

Session ID: S-ed7d82-0000211
Sensor / honeypot: T-Pot (sealed replay)
First / last UTC event: 2026-07-01T00:10:34Z / 2026-07-01T00:10:38Z
Assigned evidence marker: UBI-A6-679461BECC22

## Evidence chain

| Step | UTC | Raw artifact + locator | Observed action | Interpretation | Confidence | Alternative |
|---|---|---|---|---|---|---|
| 1 | 2026-07-01T00:10:36Z | honeypot-replay.jsonl row 213, event_id S-ed7d82-0000211-3 | auth_success | Authentication succeeded - credential accepted | high | Misconfigured service exposing test creds |
| 2 | 2026-07-01T00:10:34Z | honeypot-replay.jsonl row 1226, event_id S-ed7d82-0000211-1 | connect | Attacker established connection to honeypot | high | Legitimate scanner or researcher |
| 3 | 2026-07-01T00:10:38Z | honeypot-replay.jsonl row 4648, event_id S-ed7d82-0000211-5 | payload_download | Malware payload downloaded to honeypot | high | Test file transfer |

## Intent assessment

The most likely objective is initial access followed by malware deployment. The attacker
authenticated using credential fingerprint 1a5ace3ed07f1b60 and downloaded a payload with SHA-256
hash e1c27bf70abbabeb9ee71bffa8f9737b70361802170cbe39c11bbdc42875263f.

What supports this: successful authentication followed by payload download indicates the
attacker had valid credentials and intended to deploy malware.

What would disprove it: if the source IP is a known security research scanner, this could
be benign scanning with automated credential testing.

## ATT&CK mapping

- T1110 (Brute Force) — MQTT credential testing against honeypot
- T1059 (Command and Scripting Interpreter) — command execution post-authentication
- T1105 (Ingress Tool Transfer) — payload downloaded to honeypot

Evidence: event_ids S-ed7d82-0000211-1, S-ed7d82-0000211-3, S-ed7d82-0000211-5
Limitation: single session analysis; full campaign pattern requires cluster analysis.

## Indicator handling

Source IP: 198.51.100.155 — unique to this honeypot dataset, no reputation claim.
Credential fingerprint: 1a5ace3ed07f1b60 — shared across multiple sessions indicates credential reuse.
Payload SHA-256: e1c27bf70abbabeb9ee71bffa8f9737b70361802170cbe39c11bbdc42875263f — quarantined by hash only, never executed.

## Defensive action

Detection: Sigma rule "Honeypot Payload Download" triggers on any payload_download action.
Prevention: Restrict MQTT access to known management IPs only.
Owner: SOC Analyst team
Acceptance test: Re-run pipeline; Sigma rule must trigger on session S-ed7d82-0000211.
