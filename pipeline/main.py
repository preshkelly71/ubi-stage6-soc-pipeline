"""Main entry point for the UBI Stage 6 SOC Analysis Pipeline."""
import sys
from pipeline.orchestrator import Orchestrator

def main():
    replay_path = sys.argv[1] if len(sys.argv) > 1 else "replay/raw/honeypot-replay.jsonl"
    orchestrator = Orchestrator(replay_path)
    stats = orchestrator.run()
    print("\n=== Pipeline Statistics ===")
    print(f"Total time: {stats['total_time_seconds']}s")
    print(f"Output hashes: {len(stats['output_hashes'])} files")

if __name__ == "__main__":
    main()
