# Falcon PQC FALSIGN Engine

A Python **rule-evaluation demonstration** with a FastAPI interface, command-line batch processing, and an in-memory HMAC-SHA256 audit chain.

> **Important cryptographic limitation:** Despite the historical repository name, this code does **not** implement FN-DSA/Falcon key generation, signing, signature verification, Gaussian sampling, or NIST conformance testing. It must not be used to secure messages or validate post-quantum signatures. FN-DSA is a separate NIST standardization effort (FIPS 206). See [NIST's PQC project](https://csrc.nist.gov/Projects/pqc-dig-sig) for background.

## Functionality

- Three deterministic workers evaluate example input rules: primary metric over **25**, secondary metric over **12**, optional critical flag, and descriptor anomaly keywords.
- Produces a structured dossier with routine/elevated/critical classification and explanations.
- Signs audit-entry metadata into a chained HMAC-SHA256 ledger and verifies each signature and preceding link.
- Offers single-task and CSV batch CLI commands, a mock-only chat responder, and FastAPI endpoints.
- Serves a responsive browser console at the local server root. No build tool or external fonts are required.
- Includes legacy alternate evaluator code under `falcon_engine/`; its distinct demonstration threshold for the secondary metric is **10**, not 12.

**Limits:** The rules are illustrative, not FIPS-derived risk thresholds. The audit ledger and dossier registry exist only in process memory; neither survives a restart. The identifier filter is a best-effort regular-expression screen, **not** comprehensive PHI detection or HIPAA de-identification. Never enter real patient information.

## Install and run

Requires Python 3.10+.

```bash
git clone https://github.com/abusuraihsakhri/falcon-pqc-falsign-engine.git
cd falcon-pqc-falsign-engine
python -m pip install -e ".[dev]"
python -m pytest -q
python cli.py serve --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/** for the browser console, or **http://127.0.0.1:8000/docs** for the generated OpenAPI interface. This application is not independently hosted on GitHub Pages: the interactive console requires its same-origin Python API, which static hosting cannot run.

CLI examples:

```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --status DISCORDANT
python cli.py chat "What is the current status?"
python cli.py batch -i sample.csv -o results.csv
python cli.py verify-audit
python simulator.py 100
```

The installed `falcon-pqc-falsign-engine` entry point invokes the primary `cli.py` interface. The separate `python falcon_engine_app.py` entry point retains the alternate evaluator.

CSV files require `task_id`, `target_identifier`, and `primary_metric` headers. Optional `secondary_metric` defaults to zero; `is_critical_flag` recognizes `true/false`, `1/0`, `yes/no`, `y/n`, and `on/off` (case-insensitive). Invalid rows fail without writing a new output file.

## API and access controls

- `GET /` — browser console (needs the API running)
- `GET /health` — liveness
- `GET /metrics` — **JSON** in-memory counters (not Prometheus exposition)
- `POST /api/audit` — validate a task and return a dossier
- `POST /api/chat` — deterministic mock responder (no external LLM)
- `GET /api/audit/logs` — HMAC ledger metadata, protected by `X-Audit-Token`

Set `AUDIT_READ_TOKEN` in the server environment to permit authenticated log reads. Without it, the endpoint is disabled (HTTP 403). The other endpoints have no general authentication: **bind only to localhost, or place the application behind appropriate authentication, transport security, and rate limiting before any public deployment**.

The in-memory audit logger uses `AUDIT_SECRET_KEY` (a private, high-entropy secret). If absent, it generates a process-local random key; signatures then cannot be verified after restart. The exposed audit hashes are **HMACs of metadata, not FN-DSA signatures**. Secret keys are never sent to the browser.

## Docker

```bash
# Supply unique secret values in the deployment environment; do not commit them.
export AUDIT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export AUDIT_READ_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build -d
```

Compose binds the service to `127.0.0.1:8000`, runs the application as an unprivileged user, and requires an audit signing key. `.env.example` documents available settings; actual `.env` files are ignored by Git.

## Development and limitations

Run `python -m pytest -q` and `python -m compileall -q agents falcon_engine cli.py enrichment.py simulator.py` to check the implementation. CI tests Python 3.10, 3.11, and 3.12.

Tech stack: Python, Pydantic v2, FastAPI, Uvicorn, HTML/CSS/JavaScript, and Docker. The browser console uses standard `fetch` and is intended for current evergreen desktop and mobile browsers with JavaScript enabled. It calls the local same-origin API and does not offer offline or browser-Python execution.

The repository contains additional illustrative enrichment modules. Their names do not imply implemented clinical workflows, cryptographic algorithms, or deployed integrations.

## License

[MIT](LICENSE).
