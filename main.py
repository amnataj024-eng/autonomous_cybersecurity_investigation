"""Command-line interface for the Autonomous Cybersecurity Incident Investigation system.

Examples (from the project root):
    python main.py                       investigate every alert and print a summary
    python main.py --list                list the available alerts
    python main.py --alert-id ALR-1003   investigate one alert and print the full report
    python main.py --no-llm              force DEMO mode (rule-based only)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from agents.report_generator import render_text_report, save_report
from graph.workflow import WorkflowError, build_workflow, investigate_alert
from utils.data_loader import DATA_DIR, PROJECT_ROOT, load_alerts, load_logs, load_threat_intel
from utils.llm import get_llm_client

DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        description="Multi-agent cybersecurity incident investigation (synthetic demo data).")
    parser.add_argument("--list", action="store_true", help="list the available alerts and exit")
    parser.add_argument("--alert-id", help="investigate a single alert and print its full report")
    parser.add_argument("--no-llm", action="store_true", help="force DEMO mode (do not call Groq)")
    parser.add_argument("--no-save", action="store_true", help="do not write report files")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_REPORT_DIR,
                        help="folder for exported JSON/TXT reports (default: reports/)")
    parser.add_argument("--alerts", type=Path, default=DATA_DIR / "security_alerts.csv")
    parser.add_argument("--logs", type=Path, default=DATA_DIR / "security_logs.csv")
    parser.add_argument("--threat-intel", type=Path, default=DATA_DIR / "threat_intelligence.csv")
    return parser


def _print_table(reports: list) -> None:
    header = f"{'Alert':<10} {'Type':<28} {'Classification':<30} {'Score':>5}  {'Level':<9} Approval"
    print(header)
    print("-" * len(header))
    for rep in reports:
        risk = rep.risk
        print(f"{rep.alert.get('alert_id', '?'):<10} {str(rep.alert.get('alert_type', '?')):<28} "
              f"{rep.final_classification.value:<30} {risk.score if risk else '-':>5}  "
              f"{risk.level.value if risk else '-':<9} {rep.approval_status.value}")


def main(argv: Optional[list[str]] = None) -> int:
    """Run the CLI. Returns a process exit code."""
    if hasattr(sys.stdout, "reconfigure"):  # avoid Windows console encoding errors
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)

    try:
        alerts = load_alerts(args.alerts)
        logs = load_logs(args.logs)
        intel = load_threat_intel(args.threat_intel)
    except (OSError, ValueError) as exc:
        print(f"ERROR: could not load the data files: {exc}", file=sys.stderr)
        return 1

    if args.list:
        print(alerts[["alert_id", "timestamp", "alert_type", "severity", "source_ip", "username"]]
              .to_string(index=False))
        return 0

    llm = get_llm_client(enabled=not args.no_llm)
    print(f"Mode: {llm.mode_label}")
    print("All data is synthetic demonstration data. Recommended actions are simulated only.\n")

    graph = build_workflow(llm)
    if args.alert_id:
        match = alerts[alerts["alert_id"].str.upper() == args.alert_id.upper()]
        if match.empty:
            print(f"ERROR: alert '{args.alert_id}' not found. Use --list to see valid ids.", file=sys.stderr)
            return 1
        rows = [match.iloc[0].to_dict()]
    else:
        rows = [row.to_dict() for _, row in alerts.iterrows()]

    reports = []
    for raw in rows:
        try:
            reports.append(investigate_alert(raw, alerts, logs, intel, llm, compiled_graph=graph))
        except WorkflowError as exc:
            print(f"ERROR investigating {raw.get('alert_id')}: {exc}", file=sys.stderr)

    if not reports:
        return 1
    _print_table(reports)

    if not args.no_save:
        for rep in reports:
            save_report(rep, args.output_dir)
        print(f"\nSaved {len(reports)} report(s) (JSON + TXT) to: {args.output_dir}")

    # Show one full report: the requested alert, or the highest-risk incident.
    featured = reports[0] if args.alert_id else max(reports, key=lambda r: r.risk.score if r.risk else -1)
    print("\n" + ("FULL REPORT" if args.alert_id else "FULL REPORT FOR THE HIGHEST-RISK INCIDENT"))
    print(render_text_report(featured))
    pending = [r for r in reports if r.approval_status.value == "PENDING_HUMAN_REVIEW"]
    print(f"\n{len(pending)} incident(s) require human review (simulated approval in the dashboard).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
