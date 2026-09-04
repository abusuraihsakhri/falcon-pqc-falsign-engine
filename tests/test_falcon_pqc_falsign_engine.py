"""
Automated Pytest Test Suite for Falcon Pqc Falsign Engine.
Domain: Post-Quantum Cryptography & Hardware Security
Standard: NIST FIPS 203/204/205 / ISO/IEC 17825 Standards
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from agents.base import PHIGuard, AuditLogger, SecurityException, assert_no_phi
from agents.models import SystemTaskPayload, UrgencyLevel, SystemIntegrityStatus
from agents.workers import InvariantQCWorker, SafetyEscalationWorker, ProtocolConformanceWorker
from agents.supervisor import SystemSupervisor
from cli import main


def test_phi_guard_enforcement():
    with pytest.raises(SecurityException):
        PHIGuard.assert_no_phi("Patient MRN-994827 blood culture positive for Staphylococcus")

    # Clean text passes
    PHIGuard.assert_no_phi("Analytical assay specimen KEY-001 optimal")


def test_phi_guard_error_message_no_pattern_leak():
    """Verify PHI guard error messages do not leak regex pattern details."""
    with pytest.raises(SecurityException) as exc_info:
        assert_no_phi("Patient MRN-994827 blood culture positive")
    error_msg = str(exc_info.value)
    assert "PHI Outbound Guard Violation" in error_msg
    # Ensure no raw regex pattern is leaked in error message
    assert "MRN" not in error_msg or "identifier" in error_msg.lower()
    assert "\\b" not in error_msg  # No regex metacharacters leaked
    assert "(?:" not in error_msg  # No regex group syntax leaked


def test_phi_guard_redaction():
    """Verify PHI redaction replaces sensitive data."""
    redacted = PHIGuard.redact_phi("Patient MRN-994827 has SSN 123-45-6789")
    assert "MRN" not in redacted or "REDACTED" in redacted
    assert "123-45-6789" not in redacted
    assert "REDACTED_IDENTIFIER" in redacted


def test_specialized_workers():
    # Worker 1: QC Invariant
    p1 = SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=35.0)
    alerts1 = InvariantQCWorker.evaluate(p1)
    assert len(alerts1) == 1
    assert alerts1[0].urgency == UrgencyLevel.ELEVATED

    # Worker 2: Safety
    p2 = SystemTaskPayload(task_id="T2", target_identifier="KEY-02", primary_metric=10.0, is_critical_flag=True)
    alerts2 = SafetyEscalationWorker.evaluate(p2)
    assert len(alerts2) == 1
    assert alerts2[0].urgency == UrgencyLevel.CRITICAL_STAT

    # Worker 3: Protocol Conformance
    p3 = SystemTaskPayload(task_id="T3", target_identifier="KEY-03", primary_metric=10.0, status_descriptor="DISCORDANT_ANOMALY")
    alerts3 = ProtocolConformanceWorker.evaluate(p3)
    assert len(alerts3) == 1


def test_supervisor_consensus_and_audit():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(
        task_id="TASK-PROD-01",
        target_identifier="KEY-PROD-01",
        primary_metric=12.0,
        secondary_metric=4.0,
        status_descriptor="NOMINAL"
    )
    dossier = supervisor.process_task(payload)
    assert dossier.overall_urgency == UrgencyLevel.ROUTINE
    assert dossier.integrity_status == SystemIntegrityStatus.VALIDATED
    assert dossier.audit_hash != ""

    # Verify cryptographic audit trail
    assert AuditLogger.verify_integrity() is True

    # CLI tests
    assert main(["audit", "--task-id", "CLI-TEST-01"]) == 0
    assert main(["chat", "Explain", "specifications"]) == 0
    assert main(["verify-audit"]) == 0


def test_batch_missing_file_returns_error():
    """Verify batch command returns non-zero exit code for missing input file."""
    result = main(["batch", "-i", "nonexistent_file.csv"])
    assert result == 1


def test_nan_inf_metric_rejection():
    """Verify NaN and Inf metric values are rejected by validation."""
    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=float("nan"))

    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T2", target_identifier="KEY-02", primary_metric=10.0, secondary_metric=float("inf"))


def test_empty_string_rejection():
    """Verify empty/whitespace-only string fields are rejected."""
    with pytest.raises(ValueError):
        SystemTaskPayload(task_id="   ", target_identifier="KEY-01", primary_metric=10.0)

    with pytest.raises(ValueError):
        SystemTaskPayload(task_id="T1", target_identifier="", primary_metric=10.0)
