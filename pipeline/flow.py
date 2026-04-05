"""
Prefect orchestration flow.

Usage:
  python -m pipeline.flow                              # scan default directory
  python -m pipeline.flow --directory ./data/sample_files
  python -m pipeline.flow --directory ./data/sample_files --owner alice-uuid
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prefect import flow, task

from scanner.file_scanner import FileScanner
from pipeline.enrichment import enrich
from pipeline.db_writer import insert_scan_result
from security.insider_threat import InsiderThreatDetector


@task(retries=2, retry_delay_seconds=5, log_prints=True)
def scan_file(path: str) -> dict:
    return FileScanner().scan_file(path)


@task(log_prints=True)
def enrich_result(result: dict) -> dict:
    return enrich(result)


@task(log_prints=True)
def store_result(result: dict, owner_id: str = None) -> str:
    return insert_scan_result(result, owner_id=owner_id)


@task(log_prints=True)
def run_threat_detection(file_id: str):
    InsiderThreatDetector().evaluate(file_id)


@flow(name="data-leak-detection", log_prints=True)
def run_pipeline(directory: str = "./data/sample_files", owner_id: str = None):
    files = glob.glob(f"{directory}/**/*.*", recursive=True)
    print(f"[Pipeline] Scanning {len(files)} files in '{directory}'")

    for path in sorted(files):
        raw      = scan_file(path)
        enriched = enrich_result(raw)
        fid      = store_result(enriched, owner_id=owner_id)
        if fid:
            run_threat_detection(fid)

    print("[Pipeline] All files processed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the leak-detect Prefect pipeline")
    parser.add_argument("--directory", default="./data/sample_files",
                        help="Directory to scan (default: ./data/sample_files)")
    parser.add_argument("--owner", default=None,
                        help="User UUID to assign scanned files to")
    args = parser.parse_args()
    run_pipeline(directory=args.directory, owner_id=args.owner)
