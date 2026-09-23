from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .reporting import REVIEW_COLUMNS


ALLOWED_STATUS = {"PENDING", "IN_REVIEW", "VALIDATED", "REJECTED", "KNOWN", "DEFERRED"}
BOOL = {"true", "false"}


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REVIEW_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            errors.append(f"missing columns: {', '.join(missing)}")
            return errors
        for line_no, row in enumerate(reader, 2):
            status = (row.get("review_status") or "").strip().upper()
            if status not in ALLOWED_STATUS:
                errors.append(f"line {line_no}: invalid review_status {status!r}")
            for col in (
                "reachability_verified", "security_boundary_verified",
                "affected_version_verified", "known_advisory_verified",
            ):
                value = (row.get(col) or "").strip().lower()
                if value and value not in BOOL:
                    errors.append(f"line {line_no}: {col} must be true/false/blank")
            if status in {"VALIDATED", "REJECTED", "KNOWN"}:
                required = ["reviewer", "reviewer_decision", "reviewer_notes", "verified_at_utc"]
                for col in required:
                    if not (row.get(col) or "").strip():
                        errors.append(f"line {line_no}: {col} required when review_status={status}")
            if status == "VALIDATED":
                for col in (
                    "reachability_verified", "security_boundary_verified",
                    "affected_version_verified", "known_advisory_verified",
                ):
                    if (row.get(col) or "").strip().lower() != "true":
                        errors.append(f"line {line_no}: {col}=true required for VALIDATED")
            if status == "REJECTED" and not (row.get("false_positive_reason") or "").strip():
                errors.append(f"line {line_no}: false_positive_reason required for REJECTED")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a manually reviewed Huginn findings CSV before later ingestion.")
    parser.add_argument("csv", type=Path)
    args = parser.parse_args()
    errors = validate(args.csv)
    if errors:
        for error in errors:
            print(error)
        raise SystemExit(2)
    print("review CSV validation passed")


if __name__ == "__main__":
    main()
