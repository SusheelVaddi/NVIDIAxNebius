# Autonomous IT Reliability & Incident Recovery System

> **NVIDIA × Nebius Hackathon 2026**

An autonomous incident mitigation and recovery system that **detects** simulated IT incidents, **plans** remediation using an AI planner (or deterministic fallback), **decides** whether recovery is safe via an explainable deterministic policy gate, **executes** simulated recovery actions in-memory, **independently verifies** the resulting system state, and records an append-only chronological **audit trail**.

---

## Architecture Diagram (Text)

```
[ Incident Triggered / Detected ]
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Receive Incident (Orchestrator)                                          │
│    - Record INCIDENT_RECEIVED in Audit Log                                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Load Current System State                                                │
│    - Snapshot simulated metrics (CPU, Memory, Error Rate, Replicas)         │
│    - Record STATE_LOADED in Audit Log                                       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Propose Recovery Action (RecoveryPlanner Interface)                      │
│    ├── NebiusPlanner: NVIDIA Nemotron Model (Nebius Token Factory API)      │
│    └── Fallback: DeterministicMockPlanner (Rule-Based Offline Planner)      │
│    - Strict validation via Pydantic schema (AIPlanProposal)                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. Record Action Proposal in Audit Log (ACTION_PROPOSED)                    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. Deterministic Policy Gate (DeterministicPolicyGate)                      │
│    * THE FINAL AUTHORITY — Cannot be bypassed by AI proposals *             │
│    Checks:                                                                  │
│    [x] Action type explicitly allowed?                                      │
│    [x] Target service exists in infrastructure catalog?                     │
│    [x] Action marked safe for simulation (safe_for_simulation=True)?        │
│    [x] Required parameters present (e.g. target_instances)?                 │
│    [x] Risk level <= 5 and retry count < 3?                                 │
│    [x] Protected service rules (e.g. database critical -> manual review)?   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
           [ Verdict: APPROVE ]                  [ Verdict: DENY ]
                    │                                     │
                    ▼                                     ▼
┌──────────────────────────────────────┐     ┌────────────────────────────────┐
│ 6. Simulated Recovery Executor       │     │ Pipeline Terminated:           │
│    (SimulatedRecoveryExecutor)       │     │ - Final status: recovery_denied│
│    - Restarts failed services        │     │ - Executor/Verifier skipped    │
│    - Clears queues                   │     │ - Record in Audit Log          │
│    - Scales instances (<= max limit) │     └────────────────┬───────────────┘
│    - Record RECOVERY_EXECUTED        │                      │
└───────────────────┬──────────────────┘                      │
                    │                                         │
                    ▼                                         │
┌──────────────────────────────────────┐                      │
│ 7. Independent Verifier              │                      │
│    (IndependentVerifier)             │                      │
│    - Zero-trust independent probe    │                      │
│    - Validates status == HEALTHY     │                      │
│    - Verifies error_rate <= 0.10     │                      │
│    - Verifies action-specific checks │                      │
│    - Record VERIFICATION_COMPLETED   │                      │
└───────────────────┬──────────────────┘                      │
                    │                                         │
                    └──────────────────┬──────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 8. Record Final Pipeline Result in Audit Log (PIPELINE_COMPLETED)           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 9. Return IncidentResponse / RecoveryResponse to API Client                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Member 3 Responsibilities

Member 3 was responsible for designing, implementing, testing, and documenting the **Orchestration, Policy, Verification, AI Planning, Audit Logging, and API Layer**:

1. **Central Orchestrator (`app.orchestrator.Orchestrator`)**:
   - Built the 9-step coordinated pipeline managing lifecycle transitions from incident ingestion through verified recovery.
   - Guaranteed sequential error handling, fallback routing, and strict lifecycle status tracking (`detected`, `approved`, `rejected`, `executed`, `verified`, `failed`).

2. **Deterministic Policy Gate (`app.policy.DeterministicPolicyGate`)**:
   - Implemented the deterministic, explainable safety gate acting as the **final authority**.
   - Validates action allowlists, service existence, simulation safety flags (`safe_for_simulation`), required parameter schemas, risk limits, and protected service guardrails.

3. **Simulated Recovery Executor (`app.recovery.SimulatedRecoveryExecutor`)**:
   - Engineered in-memory execution engine safely modifying infrastructure state: service restarts, queue flushing, and instance scaling bounded by safety limits.

4. **Independent Verifier (`app.verification.IndependentVerifier`)**:
   - Designed a zero-trust verification engine that directly queries the infrastructure state post-recovery without trusting the executor's return status.

5. **Append-Only Audit Logging (`app.audit.AuditLogger`)**:
   - Built the audit logging subsystem storing chronological, tamper-evident JSONL logs capturing every decision, proposal, execution, and verification result.

6. **AI Recovery Planner & Nebius Integration (`app.recovery.RecoveryPlanner`)**:
   - Defined the abstract `RecoveryPlanner` interface isolating AI models from execution authority.
   - Built `NebiusPlanner` integrating the OpenAI-compatible Nebius Token Factory API with the NVIDIA Nemotron model (`nvidia/llama-3.1-nemotron-70b-instruct`) using strict Pydantic JSON validation (`AIPlanProposal`).
   - Created `DeterministicMockPlanner` providing offline, rule-based planning and automatic fallback.

7. **FastAPI Endpoints (`app.api.routes`)**:
   - Implemented `POST /incidents/recover`, `GET /incidents/{incident_id}/audit`, and `GET /health` with complete request and response schema models.

8. **End-to-End Demonstrations & Tests (`demo.py`, `tests/`)**:
   - Authored the comprehensive demonstration suite (`demo.py`) and full automated test suite (82 passing tests covering all success and failure branches).

---

## Setup Instructions

### Prerequisites

- Python 3.11+
- pip

### 1. Clone & Install

```bash
# Clone the repository
git clone <repo-url> && cd NVIDIAxNebius

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable development mode
pip install -e ".[dev]"
```

### 2. Run the Application Server

```bash
uvicorn app.main:app --reload
```

The FastAPI application will start at **http://127.0.0.1:8000**.
- Interactive Swagger UI: **http://127.0.0.1:8000/docs**
- ReDoc documentation: **http://127.0.0.1:8000/redoc**

### 3. Run Automated Tests

```bash
pytest -v
```

All 82 unit and integration tests will run and pass in under 1 second.

### 4. Run the End-to-End Demonstration

```bash
python3 demo.py
```

Runs all 5 scenarios with colored console output, request/response JSON previews, and audit trail inspection.

---

## Environment Variables

| Variable | Default Value | Description |
|---|---|---|
| `NEBIUS_TOKEN_FACTORY_API_KEY` | *(None / Empty)* | API Key for authenticating with the Nebius Token Factory / Nebius Studio API. |
| `NEBIUS_TOKEN_FACTORY_BASE_URL` | `https://api.studio.nebius.ai/v1` | Base URL for OpenAI-compatible Nebius chat completions. |
| `NEBIUS_MODEL` | `nvidia/llama-3.1-nemotron-70b-instruct` | NVIDIA Nemotron model hosted on Nebius Token Factory. |

---

## How to Run Without Nebius (Offline / Default)

The system is fully operational **without any external API keys or network connection**.

When `NEBIUS_TOKEN_FACTORY_API_KEY` is not set or empty:
1. `NebiusPlanner` automatically falls back to `DeterministicMockPlanner`.
2. `DeterministicMockPlanner` analyzes the incident severity, description, and system metrics locally:
   - High CPU / load $\to$ recommends `scale_service`.
   - Backlogged queue $\to$ recommends `clear_queue`.
   - Critical incident $\to$ recommends `failover`.
   - High error rate / degradation $\to$ recommends `restart_service`.
3. All operations run deterministically in-memory in milliseconds.

```bash
# Ensure no external key is set
unset NEBIUS_TOKEN_FACTORY_API_KEY

# Run the complete demonstration offline
python3 demo.py
```

---

## How to Run With Nebius (NVIDIA Nemotron)

To enable live AI planning powered by the **NVIDIA Nemotron** model on Nebius Token Factory:

```bash
# 1. Set your Nebius API Key
export NEBIUS_TOKEN_FACTORY_API_KEY="your-nebius-token-factory-key"

# 2. (Optional) Customize the endpoint or model. If unset, the system uses the Nebius Token Factory default.
export NEBIUS_TOKEN_FACTORY_BASE_URL="https://api.studio.nebius.ai/v1"
export NEBIUS_MODEL="nvidia/llama-3.1-nemotron-70b-instruct"

# 3. Start the server or run the demo
python3 demo.py
```

When the environment variable is set, the orchestrator uses `NebiusPlanner`. When it is absent or the Nebius API call fails, the system automatically falls back to `DeterministicMockPlanner` while the policy gate remains the final authority.

### How Nebius Planning Works:
1. The orchestrator calls `NebiusPlanner.plan(incident, system_state)`.
2. A structured prompt is sent to `POST /chat/completions` on Nebius Token Factory with `response_format: {"type": "json_object"}`.
3. The NVIDIA Nemotron model responds with strict structured JSON:
   ```json
   {
     "action_type": "restart_service",
     "target_service": "payment-service",
     "parameters": {},
     "reasoning": "Error rate exceeds 60% and latency is spiking. A restart clears hanging connection pools.",
     "confidence": 0.95
   }
   ```
4. The output is strictly validated against the Pydantic model `AIPlanProposal`.
5. If the Nebius API call fails, times out, or returns invalid schema, `NebiusPlanner` **gracefully falls back** to `DeterministicMockPlanner` without interrupting the recovery lifecycle.

---

## Example API Request

### Endpoint: `POST /incidents/recover`

```bash
curl -X POST http://127.0.0.1:8000/incidents/recover \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc-payment-001",
    "incident_type": "service_degraded",
    "affected_service": "payment-service",
    "proposed_recovery_action": {
      "incident_id": "inc-payment-001",
      "action_type": "restart_service",
      "target_service": "payment-service",
      "parameters": {},
      "safe_for_simulation": true,
      "risk_level": 1,
      "retry_count": 0
    },
    "current_system_state": {
      "service_name": "payment-service",
      "status": "degraded",
      "cpu_percent": 45.0,
      "memory_percent": 50.0,
      "error_rate": 0.65,
      "queue_size": 0,
      "instances": 2
    }
  }'
```

---

## Example API Response

### Status: `200 OK`

```json
{
  "incident_id": "inc-payment-001",
  "policy_decision": {
    "id": "30cc240781b1",
    "incident_id": "inc-payment-001",
    "verdict": "approve",
    "reason": "Action 'restart_service' on 'payment-service' approved: action type allowed, service exists, safe for simulation, required parameters present, and risk/retry limits satisfied.",
    "decided_by": "DeterministicPolicyGate",
    "decided_at": "2026-10-27T15:12:06.944114Z"
  },
  "recovery_result": {
    "id": "882430b33592",
    "action_id": "78a0741b2325",
    "incident_id": "inc-payment-001",
    "action_type": "restart_service",
    "target_service": "payment-service",
    "success": true,
    "message": "Service 'payment-service' successfully restarted.",
    "started_at": "2026-10-27T15:12:06.944173Z",
    "completed_at": "2026-10-27T15:12:06.944182Z"
  },
  "verification_result": {
    "id": "a2e092d62c0c",
    "incident_id": "inc-payment-001",
    "service_name": "payment-service",
    "outcome": "pass",
    "details": "Independent verification passed: service is healthy, error_rate=0.01, cpu=20.0%, mem=30.0%, instances=2, queue_size=0.",
    "checks_performed": [
      "service_exists:PASS",
      "status_healthy:PASS",
      "error_rate_acceptable:PASS(0.01)"
    ],
    "checked_at": "2026-10-27T15:12:06.944245Z"
  },
  "final_status": "success",
  "audit_events": [
    {
      "id": "90d1bf37e891",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.943801Z",
      "component_name": "Orchestrator",
      "event_type": "incident_received",
      "details": {
        "incident": {
          "id": "inc-payment-001",
          "service_name": "payment-service",
          "severity": "high",
          "title": "service_degraded on payment-service",
          "status": "detected"
        }
      },
      "success": true,
      "explanation": "Incident received: 'service_degraded on payment-service' on service 'payment-service' with severity 'high'."
    },
    {
      "id": "4220b3cd6749",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.943836Z",
      "component_name": "Orchestrator",
      "event_type": "state_loaded",
      "details": {
        "system_state_before": {
          "service_name": "payment-service",
          "status": "degraded",
          "cpu_percent": 45.0,
          "error_rate": 0.65
        }
      },
      "success": true,
      "explanation": "Loaded system state snapshot for 'payment-service'."
    },
    {
      "id": "dbfa6712e19a",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.944055Z",
      "component_name": "RecoveryPlanner",
      "event_type": "action_proposed",
      "details": {
        "recovery_action": {
          "action_type": "restart_service",
          "target_service": "payment-service"
        },
        "planner": "DeterministicMockPlanner"
      },
      "success": true,
      "explanation": "RecoveryPlanner (DeterministicMockPlanner) recommended action 'restart_service' targeting service 'payment-service' with parameters {'severity': 'medium'}."
    },
    {
      "id": "edd869fe22e4",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.944125Z",
      "component_name": "DeterministicPolicyGate",
      "event_type": "policy_evaluated",
      "details": {
        "policy_decision": {
          "verdict": "approve",
          "reason": "Action 'restart_service' on 'payment-service' approved..."
        }
      },
      "success": true,
      "explanation": "Policy decision: approve. Rationale: Action 'restart_service' on 'payment-service' approved..."
    },
    {
      "id": "0d4c701ba507",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.944198Z",
      "component_name": "SimulatedRecoveryExecutor",
      "event_type": "recovery_executed",
      "details": {
        "recovery_result": {
          "success": true,
          "message": "Service 'payment-service' successfully restarted."
        }
      },
      "success": true,
      "explanation": "Service 'payment-service' successfully restarted."
    },
    {
      "id": "ab5543dbd489",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.944253Z",
      "component_name": "IndependentVerifier",
      "event_type": "verification_completed",
      "details": {
        "verification_result": {
          "outcome": "pass",
          "details": "Independent verification passed: service is healthy..."
        }
      },
      "success": true,
      "explanation": "Independent verification passed: service is healthy, error_rate=0.01..."
    },
    {
      "id": "b6e6f3ee3a2a",
      "incident_id": "inc-payment-001",
      "timestamp": "2026-10-27T15:12:06.944297Z",
      "component_name": "Orchestrator",
      "event_type": "pipeline_completed",
      "details": {
        "pipeline_status": "success",
        "incident_status": "verified"
      },
      "success": true,
      "explanation": "Incident recovery pipeline completed with status 'success'."
    }
  ]
}
```

---

## Security Limitations & Guardrails

1. **In-Memory Simulation Boundary**:
   - The entire infrastructure catalog and recovery executor operate strictly on in-memory simulated objects (`InfrastructureSimulator`).
   - No operating system subprocesses, live cloud APIs (AWS/GCP/Azure), Kubernetes clusters, or production networks can be modified or accessed by this system.

2. **Policy Gate as Absolute Authority**:
   - The AI planner (`NebiusPlanner`) has **zero execution authority**.
   - A model recommendation cannot execute actions directly, cannot approve itself, and cannot bypass the deterministic policy gate.
   - Even high-confidence AI proposals are blocked if they violate allowlists, simulation safety flags, or risk limits.

3. **Protection Against Prompt Injection & Hallucinations**:
   - All AI output is parsed into strict Pydantic schemas (`AIPlanProposal`). Extraneous commands, markdown artifacts, or unexpected keys cause immediate validation failure, which safely triggers fallback to rule-based planning.

4. **Protected Services Quarantine**:
   - Critical services (e.g. `database`) are tagged in `DEFAULT_PROTECTED_SERVICES`. Any automated recovery attempt during critical incidents is intercepted by the policy gate and routed to `MANUAL_REVIEW`, preventing unintended database restarts or failovers.

5. **Operational Risk & Retry Throttling**:
   - Actions with a risk score greater than `max_risk_limit` (default: 5) or actions that have reached `max_retry_limit` (default: 3 retries) are rejected by the policy gate, preventing flapping recovery cycles.
   - Instance scaling has a hard executor upper boundary (`max_scale_limit = 10`) to eliminate simulated resource starvation.

---

## License

Hackathon project — NVIDIA × Nebius 2026.