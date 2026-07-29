# Portfolio Continuity Record

## Stage 6 Project 2: Engineer a Deception Sensor and Analysis Pipeline

### Previous-stage component reused

Stage 5 (Threat Hunt): The hunt engine pattern and evidence model structure.
The event normalization approach (schema detection, canonical event building,
provenance tracking via source_file + row_number) was adapted from the Stage 5
hunt engine's data ingestion pattern.

### Interface consumed

- Stage 5 hunt engine: raw event ingestion and schema detection interface
- Extended in Stage 6: added T-Pot replay adapter, sessionization, clustering,
  payload handling, STIX 2.1 generation, and detection rule writing

### Backward-compatible extension

The Stage 6 pipeline extends the Stage 5 evidence model by:
1. Adding sessionization (connection_id grouping + boundary detection)
2. Adding clustering (IP, credential, payload dimensions)
3. Adding STIX 2.1 output (deterministic UUIDs)
4. Adding Sigma + Suricata detection rule generation
5. Preserving raw-to-result provenance for every derived output

### Evidence that prior provenance remains intact

All canonical events retain source_file and row_number fields from Stage 5.
The pipeline traces from raw replay event → normalized event → session →
cluster → STIX indicator → detection rule with full lineage.

### Migration record

No incompatible changes. The Stage 5 adapter pattern was extended, not replaced.
Schema detection was enhanced to support schema_version field ("1"/"2") in
addition to connection_id prefix detection.

### Component handed to next stage

- T-Pot replay adapter (normalized sessions)
- Cluster definitions (IP, credential, payload groupings)
- Detection rules (Sigma, Suricata)
- STIX 2.1 bundle with deterministic indicators

These components are available for the network range project and capstone.
