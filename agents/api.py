"""FastAPI interface for the demonstrative rule-evaluation service."""
import os
import hmac
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .base import AuditLogger, SecurityException
from .models import SystemTaskPayload
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Falcon PQC FALSIGN Rule Evaluation API",
    description="Demonstration threshold/keyword evaluator; not an FN-DSA signature implementation.",
    version="3.0.0",
)


class ChatRequest(BaseModel):
    query: str


@app.get("/")
def console():
    return FileResponse(Path(__file__).resolve().parent.parent / "web" / "index.html")


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "falcon-pqc-falsign-engine", "version": "3.0.0"}


@app.get("/metrics")
def metrics():
    """Return JSON counters, not Prometheus exposition format."""
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "system_status": "READY",
    }


@app.post("/api/audit")
def api_audit(payload: SystemTaskPayload):
    try:
        return supervisor.process_task(payload).to_dict()
    except SecurityException:
        raise HTTPException(status_code=422, detail="Potentially sensitive identifier in input") from None


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        return {"response": supervisor.query_supervisory_chat(req.query)}
    except SecurityException:
        raise HTTPException(status_code=422, detail="Potentially sensitive identifier in query") from None


@app.get("/api/audit/logs")
def api_audit_logs(x_audit_token: str | None = Header(default=None)):
    token = os.getenv("AUDIT_READ_TOKEN")
    if not token or not x_audit_token or not hmac.compare_digest(token, x_audit_token):
        raise HTTPException(status_code=403, detail="Audit log access is disabled or unauthorized")
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}
