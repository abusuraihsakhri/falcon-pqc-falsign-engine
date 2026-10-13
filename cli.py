"""
Command Line Interface for Falcon Pqc Falsign Engine.
"""
import argparse
import csv
import json
import os
import sys
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from agents.base import AuditLogger, SecurityException

supervisor = SystemSupervisor(model_provider="mock")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="falcon-pqc-falsign-engine", description="Falcon Pqc Falsign Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Audit
    p_audit = subparsers.add_parser("audit", help="Run single task evaluation")
    p_audit.add_argument("--task-id", default="TASK-2026-001")
    p_audit.add_argument("--target", default="KEY-TARGET-01")
    p_audit.add_argument("--primary", type=float, default=28.5)
    p_audit.add_argument("--secondary", type=float, default=14.2)
    p_audit.add_argument("--critical", action="store_true")
    p_audit.add_argument("--status", default="DISCORDANT")

    # Chat
    p_chat = subparsers.add_parser("chat", help="System configuration query")
    p_chat.add_argument("query", nargs="+")

    # Batch
    p_batch = subparsers.add_parser("batch", help="Batch process CSV records")
    p_batch.add_argument("-i", "--input", required=True)
    p_batch.add_argument("-o", "--output", default="results.csv")

    # Verify Audit
    subparsers.add_parser("verify-audit", help="Verify HMAC audit trail integrity")

    # Serve
    p_serve = subparsers.add_parser("serve", help="Launch FastAPI REST server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)

    if args.command == "audit":
        payload = SystemTaskPayload(
            task_id=args.task_id,
            target_identifier=args.target,
            primary_metric=args.primary,
            secondary_metric=args.secondary,
            status_descriptor=args.status,
            is_critical_flag=args.critical,
        )
        dossier = supervisor.process_task(payload)
        print("=" * 80)
        print(f"  FALCON PQC FALSIGN ENGINE")
        print(f"  Domain: Post-Quantum Cryptography & Hardware Security | Rules: illustrative thresholds (not cryptographic conformance)")
        print(f"  Dossier ID: {dossier.dossier_id} | Urgency: [{dossier.overall_urgency.value}]")
        print("=" * 80)
        for a in dossier.alerts:
            print(f"\n  [{a.urgency.value}] from {a.origin_worker}:")
            print(f"  Summary: {a.summary}")
            print(f"  Details: {a.technical_details}")
            print(f"  Action:  {a.actionable_remediation}")
        print(f"\n  HMAC-SHA256 Audit Hash: {dossier.audit_hash}")
        print("=" * 80)
        return 0

    if args.command == "chat":
        ans = supervisor.query_supervisory_chat(" ".join(args.query))
        print(f"\n[Falcon Pqc Falsign Engine Supervisor]:\n{ans}\n")
        return 0

    if args.command == "verify-audit":
        trail = AuditLogger.get_trail()
        valid = AuditLogger.verify_integrity()
        print(f"Audit Trail Blocks: {len(trail)} | Cryptographic Integrity Verified: {valid}")
        return 0

    if args.command == "batch":
        def parse_boolean(value: str) -> bool:
            normalized = str(value or "").strip().lower()
            if normalized in ("true", "1", "yes", "y", "on"):
                return True
            if normalized in ("false", "0", "no", "n", "off", ""):
                return False
            raise ValueError("Invalid boolean field")

        if not os.path.isfile(args.input):
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            return 1
        try:
            with open(args.input, mode="r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fieldnames = list(reader.fieldnames or [])
                required = {"task_id", "target_identifier", "primary_metric"}
                if not required.issubset(fieldnames):
                    print("Error: CSV must contain task_id, target_identifier, primary_metric", file=sys.stderr)
                    return 1
                out_fields = list(dict.fromkeys(
                    fieldnames + ["overall_urgency", "integrity_status", "total_alerts", "audit_hash"]
                ))
                out_rows = []
                for row_number, r in enumerate(reader, start=2):
                    try:
                        payload = SystemTaskPayload(
                            task_id=r["task_id"],
                            target_identifier=r["target_identifier"],
                            primary_metric=float(r["primary_metric"]),
                            secondary_metric=float(r.get("secondary_metric") or 0.0),
                            status_descriptor=r.get("status_descriptor") or "NOMINAL",
                            is_critical_flag=parse_boolean(r.get("is_critical_flag", "")),
                        )
                        dossier = supervisor.process_task(payload)
                    except (ValueError, TypeError, SecurityException) as exc:
                        print(f"Error: Invalid data at CSV row {row_number} ({type(exc).__name__})", file=sys.stderr)
                        return 1
                    row = dict(r)
                    row.update(
                        overall_urgency=dossier.overall_urgency.value,
                        integrity_status=dossier.integrity_status.value,
                        total_alerts=dossier.total_alerts,
                        audit_hash=dossier.audit_hash,
                    )
                    out_rows.append(row)
            with open(args.output, mode="w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=out_fields)
                writer.writeheader()
                writer.writerows(out_rows)
        except OSError as exc:
            print(f"Error: Unable to read or write CSV ({type(exc).__name__})", file=sys.stderr)
            return 1
        print(f"Processed {len(out_rows)} records -> {args.output}")
        return 0

    if args.command == "serve":
        import uvicorn
        from agents.api import app
        print(f"Starting Falcon Pqc Falsign Engine API server on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
