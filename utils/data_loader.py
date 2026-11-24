"""Loading and validating the CSV datasets (alerts, logs, threat intelligence)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

ALERT_COLUMNS = [
    "alert_id", "timestamp", "alert_type", "severity", "source_ip", "destination_ip",
    "username", "hostname", "description", "event_count", "file_hash", "domain", "rule_name",
]
LOG_REQUIRED = ["timestamp", "event_type", "source_ip"]
LOG_COLUMNS = [
    "timestamp", "event_type", "status", "username", "source_ip", "destination_ip",
    "hostname", "country", "destination_port", "bytes_out", "resource", "domain", "file_hash",
]
TI_COLUMNS = [
    "indicator", "indicator_type", "threat_type", "confidence", "status",
    "description", "source", "first_seen",
]

PathOrFile = Union[str, Path, Any]


@dataclass
class ValidationReport:
    """Result of validating a loaded dataset."""

    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rows_in: int = 0
    rows_kept: int = 0


def read_csv_strings(source: PathOrFile) -> pd.DataFrame:
    """Read a CSV as strings so IDs and IPs are never reinterpreted."""
    return pd.read_csv(source, dtype=str, keep_default_na=False)


def validate_logs(df: pd.DataFrame) -> tuple[pd.DataFrame, ValidationReport]:
    """Validate and normalise a security-log DataFrame.

    Missing optional columns are added as empty; rows with unparsable timestamps are
    dropped and reported. The returned frame has a UTC ``timestamp`` column.
    """
    report = ValidationReport(rows_in=len(df))
    if df is None or df.empty:
        report.valid = False
        report.errors.append("The log file is empty.")
        return pd.DataFrame(columns=LOG_COLUMNS), report

    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in LOG_REQUIRED if c not in df.columns]
    if missing:
        report.valid = False
        report.errors.append(f"Missing required column(s): {', '.join(missing)}")
        return pd.DataFrame(columns=LOG_COLUMNS), report

    for col in LOG_COLUMNS:
        if col not in df.columns:
            df[col] = ""
            if col not in LOG_REQUIRED:
                report.warnings.append(f"Optional column '{col}' not found; filled with blanks.")
    df = df[LOG_COLUMNS].fillna("")

    parsed = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    bad = int(parsed.isna().sum())
    if bad:
        report.warnings.append(f"{bad} row(s) dropped because the timestamp could not be parsed.")
    df["timestamp"] = parsed
    df = df[parsed.notna()].copy()

    for col in ("destination_port", "bytes_out"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in LOG_COLUMNS:
        if col not in ("timestamp", "destination_port", "bytes_out"):
            df[col] = df[col].astype(str).str.strip()
    df["status"] = df["status"].str.lower()
    df["event_type"] = df["event_type"].str.lower()

    df = df.sort_values("timestamp").reset_index(drop=True)
    report.rows_kept = len(df)
    if df.empty:
        report.valid = False
        report.errors.append("No valid rows remain after validation.")
    return df, report


def validate_alerts(df: pd.DataFrame) -> tuple[pd.DataFrame, ValidationReport]:
    """Light structural validation of an alerts DataFrame (row-level checks happen in the triage agent)."""
    report = ValidationReport(rows_in=len(df))
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    for col in ("alert_id", "timestamp", "alert_type", "severity"):
        if col not in df.columns:
            report.valid = False
            report.errors.append(f"Missing required column: {col}")
    if not report.valid:
        return pd.DataFrame(columns=ALERT_COLUMNS), report
    for col in ALERT_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[ALERT_COLUMNS].fillna("")
    report.rows_kept = len(df)
    return df.reset_index(drop=True), report


def load_alerts(path: PathOrFile = DATA_DIR / "security_alerts.csv") -> pd.DataFrame:
    """Load the security alerts CSV."""
    df, report = validate_alerts(read_csv_strings(path))
    if not report.valid:
        raise ValueError("; ".join(report.errors))
    return df


def load_logs(path: PathOrFile = DATA_DIR / "security_logs.csv") -> pd.DataFrame:
    """Load and normalise the security logs CSV."""
    df, report = validate_logs(read_csv_strings(path))
    if not report.valid:
        raise ValueError("; ".join(report.errors))
    return df


def load_threat_intel(path: PathOrFile = DATA_DIR / "threat_intelligence.csv") -> pd.DataFrame:
    """Load the local (synthetic) threat-intelligence CSV."""
    df = read_csv_strings(path)
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in ("indicator", "indicator_type", "status") if c not in df.columns]
    if missing:
        raise ValueError(f"Threat intelligence file is missing column(s): {', '.join(missing)}")
    for col in TI_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[TI_COLUMNS].copy()
    df["indicator"] = df["indicator"].str.strip().str.lower()
    df["indicator_type"] = df["indicator_type"].str.strip().str.lower()
    df["status"] = df["status"].str.strip().str.lower()
    return df
