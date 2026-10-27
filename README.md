# Autonomous IT Reliability & Incident Recovery System

> **NVIDIA × Nebius Hackathon**

An autonomous system that **detects** simulated IT incidents, **decides** whether recovery is safe via a deterministic policy gate, **executes** a simulated recovery action, **independently verifies** the result, and records a complete **audit trail**.

Everything runs locally and deterministically — no real cloud infrastructure or destructive commands.

---

## Architecture & Orchestration Flow

```
1. Receive Incident ────────▶ 2. Load System State ────────▶ 3. Propose Recovery Action
                                                                       │
┌───────────────────────────┐                                          ▼
│ 6. Independent Verifier   │◀──── 5. Simulated Executor ◀──── 4. Deterministic Policy Gate
│    (Inspects State)       │      (Restart / Queue / Scale)       (Allowed / Safe / Limits)
└─────────────┬─────────────┘
              │
              ▼
   7. Record Audit Events ───▶ 8. Complete IncidentResponse
   (Ordered, Explanatory)
```

### Components

| Component | Class | Responsibility |
|---|---|---|
| **Orchestrator** | `app.orchestrator.Orchestrator` | Coordinates the full 8-step lifecycle, error handling, and response construction. |
| **DeterministicPolicyGate** | `app.policy.DeterministicPolicyGate` | Deterministic and explainable gate; validates action type, service existence, simulation safety, required parameters, and risk/retry limits. |
| **SimulatedRecoveryExecutor** | `app.recovery.SimulatedRecoveryExecutor` | Mutates in-memory state: restarts failed services, clears queues, scales instances within limits. |
| **IndependentVerifier** | `app.verification.IndependentVerifier` | Independently queries infrastructure post-execution without trusting the executor's return value. |
| **AuditLogger** | `app.audit.AuditLogger` | Append-only logger recording every pipeline step with event ID, incident ID, timestamp, component name, event type, action/decision details, success/failure, and human-readable explanation. |
| **Infrastructure** | `app.infrastructure.InfrastructureSimulator` | In-memory simulated fleet of services (CPU, memory, error rates, queue sizes, replicas). |

---

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Setup

```bash
# Clone the repo
git clone <repo-url> && cd NVIDIAxNebius

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"
```

### Run the Server

```bash
uvicorn app.main:app --reload
```

The server starts at **http://127.0.0.1:8000**.

### Try It Out

```bash
# Health check
curl http://127.0.0.1:8000/health

# List simulated services
curl http://127.0.0.1:8000/api/services

# Inject an incident and trigger recovery
curl -X POST http://127.0.0.1:8000/api/incidents \
  -H "Content-Type: application/json" \
  -d '{"service_name": "web-frontend", "severity": "high"}'

# View audit trail
curl http://127.0.0.1:8000/api/audit

# Reset everything
curl -X POST http://127.0.0.1:8000/api/reset
```

### Interactive API Docs

FastAPI auto-generates docs at:

- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc

---

## Run Tests

```bash
pytest -v
```

Tests include coverage for:
- Approved action
- Rejected unsafe action
- Unknown service
- Missing parameters
- Executor failure
- Verification failure
- Audit events written in correct sequential order
- Simulated queue clearing
- Scaling services within configured limits
- API and model validation

---

## License

Hackathon project — NVIDIA × Nebius 2026.