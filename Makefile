.PHONY: install test fixtures analyze clean all

all: install test analyze

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --tb=short

fixtures:
	pytest tests/test_fixtures.py -v

analyze:
	python -m pipeline.main

clean:
	rm -f analysis-pipeline/sessions.parquet
	rm -f analysis-pipeline/clusters.json
	rm -f analysis-pipeline/stix-bundle.json
	rm -f analysis-pipeline/hash-ledger.csv
	rm -f analysis-pipeline/detections/suricata.rules
	rm -f analysis-pipeline/detections/sigma/*.yml
	rm -f quarantine/quarantined.jsonl
	rm -f derived/*.parquet
	rm -f tests/test-results.xml
