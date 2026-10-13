"""Security and workflow regression tests."""
import csv
import json

import pytest
from fastapi.testclient import TestClient

from agents.api import app
from agents.base import AuditTrail, SecurityException
from agents.llm_factory import LLMFactory
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from cli import main


def test_hmac_chain_detects_mutations():
    trail = AuditTrail(secret_key="isolated-test-key")
    trail.log("worker", "test", "EVENT", {"status": "OK"})
    trail.log("worker", "test", "NEXT", {"status": "OK"})
    assert trail.verify_integrity()

    snapshot = trail.get_trail()
    snapshot[0]["actor"] = "changed"
    assert trail.verify_integrity(), "Public log snapshots must not expose mutable state"

    for field in ("actor", "timestamp", "payload_hash", "current_hash", "prev_hash"):
        original = trail.logs[0][field]
        trail.logs[0][field] = "tampered"
        assert not trail.verify_integrity(), field
        trail.logs[0][field] = original
    assert trail.verify_integrity()


def test_nested_sensitive_identifier_is_blocked():
    payload = SystemTaskPayload(
        task_id="TEST", target_identifier="KEY-01", primary_metric=5,
        attributes={"context": {"operator_email": "patient@example.com"}}
    )
    with pytest.raises(SecurityException):
        SystemSupervisor().process_task(payload)


def test_unimplemented_llm_providers_are_rejected():
    with pytest.raises(ValueError, match="only the local mock"):
        LLMFactory.create("openai")
    assert "No language model" in LLMFactory.create("mock").invoke("status")


def test_batch_csv_boolean_parsing_and_validation(tmp_path):
    source = tmp_path / "cases.csv"
    result = tmp_path / "output.csv"
    with source.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "task_id", "target_identifier", "primary_metric", "secondary_metric",
            "status_descriptor", "is_critical_flag"
        ])
        writer.writeheader()
        writer.writerow(dict(task_id="A", target_identifier="KEY-01", primary_metric=5,
                             secondary_metric=0, status_descriptor="NOMINAL", is_critical_flag="False"))
        writer.writerow(dict(task_id="B", target_identifier="KEY-02", primary_metric=5,
                             secondary_metric=0, status_descriptor="NOMINAL", is_critical_flag="True"))
    assert main(["batch", "-i", str(source), "-o", str(result)]) == 0
    with result.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["overall_urgency"] == "ROUTINE"
    assert rows[1]["overall_urgency"] == "CRITICAL_STAT_PANIC"

    source.write_text(
        "task_id,target_identifier,primary_metric,is_critical_flag\n"
        "X,KEY-03,5,maybe\n", encoding="utf-8"
    )
    assert main(["batch", "-i", str(source), "-o", str(result)]) == 1


def test_api_console_metrics_and_audit_authorization(monkeypatch):
    monkeypatch.setenv("AUDIT_READ_TOKEN", "non-public-test-token")
    client = TestClient(app)
    home = client.get("/")
    assert home.status_code == 200
    assert "Rule Evaluation Console" in home.text
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert metrics.json()["system_status"] == "READY"
    assert client.get("/api/audit/logs").status_code == 403
    assert client.get("/api/audit/logs", headers={"X-Audit-Token": "wrong"}).status_code == 403
    assert client.get("/api/audit/logs", headers={"X-Audit-Token": "non-public-test-token"}).status_code == 200

    data = {"task_id": "HTTP-1", "target_identifier": "KEY-01", "primary_metric": 5.0}
    response = client.post("/api/audit", json=data)
    assert response.status_code == 200
    assert response.json()["overall_urgency"] == "ROUTINE"
    assert client.post("/api/audit", json={**data, "attributes": {"email": "alice@example.com"}}).status_code == 422
    assert client.post("/api/chat", json={"query": "MRN-123456"}).status_code == 422


def test_audit_logs_disabled_without_secret(monkeypatch):
    monkeypatch.delenv("AUDIT_READ_TOKEN", raising=False)
    assert TestClient(app).get("/api/audit/logs", headers={"X-Audit-Token": "anything"}).status_code == 403


def test_alternate_evaluator_rejects_nonfinite_inputs():
    from falcon_engine.models import FrontierPayload
    with pytest.raises(ValueError, match="finite"):
        FrontierPayload("TASK", "KEY", float("nan"), 0, "NOMINAL")
    with pytest.raises(ValueError, match="nonempty"):
        FrontierPayload("", "KEY", 10, 0, "NOMINAL")


def test_alternate_batch_false_flag(tmp_path):
    from falcon_engine.cli import main as alternate_main
    path = tmp_path / "secondary.csv"
    output = tmp_path / "secondary_results.csv"
    path.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,status_descriptor,is_critical_flag\n"
        "T1,KEY-01,5,0,NOMINAL,False\n", encoding="utf-8"
    )
    assert alternate_main(["batch", "-i", str(path), "-o", str(output)]) == 0
    with output.open(newline="", encoding="utf-8") as f:
        data = list(csv.DictReader(f))
    assert data[0]["overall_status"] == "NOMINAL_OPTIMAL"


def test_static_api_reference_has_live_paths():
    from pathlib import Path
    reference = json.loads((Path(__file__).parent.parent / "openapi_spec.json").read_text(encoding="utf-8"))
    assert set(reference["paths"]) <= set(app.openapi()["paths"])
