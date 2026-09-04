# Falcon PQC FALSIGN Engine

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

**Falcon PQC FALSIGN Engine** is an advanced analytical and computational platform implementing NIST FN-DSA Falcon fast-Fourier lattice signature engine with Gaussian trapdoor sampling. It provides a multi-agent evaluation system that processes task payloads through specialized workers to generate consensus dossiers with cryptographic audit trails.

---

## ⚙️ Key Capabilities & Algorithmic Modules

- **Deterministic Calculation Engine**: Strict compliance with standard reference formulations and thresholds.
- **Risk & Urgency Classification**: Multi-tier categorization with automated clinical/operational action recommendations.
- **Validation & Guardrails**: Rigorous input bounds checking and anomaly detection.
- **Multi-Agent Consensus**: InvariantQC, SafetyEscalation, and ProtocolConformance workers evaluate each task.
- **HMAC-SHA256 Audit Trail**: Cryptographically chained, tamper-evident logging for every evaluation.
- **Zero-PHI Outbound Guard**: Active pattern detection blocking SSNs, MRNs, phone numbers, and patient identifiers.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/falcon-pqc-falsign-engine.git
cd falcon-pqc-falsign-engine

# Install dependencies
pip install fastapi uvicorn pydantic pytest
```

### Environment Variables

| Variable | Description | Default |
|:---------|:------------|:--------|
| `AUDIT_SECRET_KEY` | Secret key for HMAC-SHA256 audit trail signing | Auto-generated (ephemeral) |
| `MODEL_PROVIDER` | LLM provider for chat (`mock`, `ollama`, `claude`, `openai`) | `mock` |

> **Security Note:** Always set `AUDIT_SECRET_KEY` in production to ensure audit trail signatures persist across restarts.

---

## 💻 CLI Quickstart & Usage

### 1. Run Single Task Evaluation
```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

### 2. Interactive Chat Query
```bash
python cli.py chat "What is the system status?"
```

### 3. Batch Process CSV Records
```bash
python cli.py batch -i sample.csv -o results.csv
```

### 4. Verify Audit Trail Integrity
```bash
python cli.py verify-audit
```

### 5. Launch FastAPI REST Server
```bash
python cli.py serve --host 127.0.0.1 --port 8000
```

### Parameter Reference
- `--task-id`: Unique task identifier (required)
- `--target`: Target entity identifier (required)
- `--primary`: Primary metric value (float, required)
- `--secondary`: Secondary metric value (float, default: 0.0)
- `--critical`: Emergency escalation flag (boolean)
- `--status`: Status descriptor (default: "NOMINAL")

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `task_id` | Unique task identifier | Required |
| `target_identifier` | Target entity identifier | Required |
| `primary_metric` | Primary measurement value (finite float) | Required |
| `secondary_metric` | Secondary measurement value (finite float) | Optional |
| `is_critical_flag` | Emergency escalation trigger | Optional |
| `status_descriptor` | Status code or phenotype descriptor | Optional |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Input Validation:** NaN/Inf rejection and string sanitization on all metric inputs.
* **Secure Defaults:** Audit secret key auto-generated if not provided; no hardcoded credentials.
* **Error Handling:** Graceful handling of missing files and invalid inputs without exposing internal details.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py 1000
```

### Test Coverage

- PHI guard enforcement and redaction
- Input validation (NaN/Inf rejection, empty string rejection)
- Worker agent evaluation logic
- Supervisor consensus and audit trail integrity
- CLI command handling (audit, chat, batch, verify-audit)
- Error handling (missing files, invalid inputs)

---

## 🐳 Container Deployment

```bash
docker build -t falcon-pqc-falsign-engine .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY=your-secure-key falcon-pqc-falsign-engine
```

Or using Docker Compose:

```bash
docker-compose up -d
```

---

## 📁 Project Structure

```
falcon-pqc-falsign-engine/
├── agents/                  # Core agent system
│   ├── api.py              # FastAPI REST server
│   ├── base.py             # Security, PHI guard, audit trail
│   ├── models.py           # Pydantic data models
│   ├── supervisor.py       # Multi-agent orchestrator
│   ├── workers.py          # Specialized evaluation workers
│   ├── llm_factory.py      # LLM provider factory
│   ├── metrics.py          # Prometheus metrics exporter
│   ├── streamer.py         # WebSocket telemetry streamer
│   └── learning.py         # Bayesian calibration engine
├── falcon_engine/          # Alternative FN-DSA engine implementation
│   ├── agents.py           # Sub-agent coordination
│   ├── engine.py           # Core algorithmic engine
│   ├── models.py           # Data models
│   ├── cli.py              # CLI interface
│   └── server.py           # FastAPI server
├── tests/                  # Pytest test suite
├── web/                    # Operations console (HTML)
├── cli.py                  # Main CLI entry point
├── simulator.py            # High-throughput simulation
├── enrichment.py           # Enrichment feature modules
├── Dockerfile             # Container definition
├── docker-compose.yml     # Multi-container orchestration
└── pyproject.toml         # Project metadata and dependencies
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
