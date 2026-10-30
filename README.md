# Autonomous IT Reliability & Incident Recovery System

Autonomous simulated IT incident recovery with NVIDIA Nemotron diagnosis, a deterministic policy gate, independent verification, and an append-only audit trail.

The system detects or receives incidents, gathers simulated service state, diagnoses and plans advisory recovery actions, gates every proposed action deterministically, executes approved actions only in memory, verifies the result independently, and records the lifecycle in an integrity-checked audit log.

## Architecture

```text
Telemetry ──> src/monitoring (detection) ──> Incident
                                                  │
                                                  ▼
                                     app/ (recovery orchestration)
                               ┌─────────────────────────────────────┐
                               │ State snapshot                      │
                               │ Nemotron diagnosis (optional)       │
                               │ AI or deterministic recovery plan   │
                               │ Append-only audit events            │
                               └──────────────────┬──────────────────┘
                                                  │ proposal only
                                                  ▼
                                   DeterministicPolicyGate
                                      │             │
                                    approve        reject
                                      │             └──> No execution
                                      ▼
                          In-memory simulated executor
                                      │
                                      ▼
                           Independent verification
                                      │
                                      ▼
                         Hash-chain audit verification
```

`src/monitoring` provides telemetry models and deterministic detection. `app/` contains the FastAPI API and recovery orchestration, diagnosis, planner, policy, simulator, verifier, and audit logger. AI output is advisory; it cannot approve or execute actions.

## Requirements and setup

Python 3.11 or newer is required. Install with pip or uv:
7. **FastAPI Endpoints & Dashboard (`app.api.routes`, `frontend/index.html`)**:
   - Implemented `POST /incidents/recover`, `POST /incidents`, `GET /services`, `GET /audit`, `GET /incidents/{id}/audit`, `GET /audit/verify`, `POST /reset`, and `GET /health`.
   - Bundled the single-page incident recovery web dashboard served at `GET /` and `GET /dashboard`.

8. **End-to-End Demonstrations & Tests (`demo.py`, `tests/`)**:
   - Authored the comprehensive multi-scenario demonstration suite (`demo.py`) and full automated test suite (319 passing tests covering diagnosis, policy safety, verifier, audit hash chain, API, and frontend integration).

---

## Setup Instructions

### Prerequisites

- Python 3.11+
- pip

### 1. Clone & Install

```bash
git clone https://github.com/SusheelVaddi/NVIDIAxNebius.git
cd NVIDIAxNebius
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Alternatively:

```bash
uv sync --extra dev
```

Copy `.env.example` to `.env` to configure the optional Nebius integration. Values in the process environment take precedence over `.env`.

## Run offline

No API key or network access is needed for the deterministic offline workflow. AI diagnosis is disabled by default, and the planner uses its deterministic rule-based implementation when no Nebius key is configured.

```bash
python demo.py
uvicorn app.main:app --reload
```

The dashboard is served at <http://127.0.0.1:8000/>. API documentation is at <http://127.0.0.1:8000/docs>. All service state and recovery execution are simulated in memory.
All 319 unit and integration tests will run and pass in ~4 seconds.

To explicitly select mock mode:

```bash
NEBIUS_MOCK_MODE=true python demo.py
```

## Run with Nebius
Runs all 5 scenarios with colored console output, request/response JSON previews, and audit trail inspection.

---

## Environment Variables

| Variable | Default Value | Description |
|---|---|---|
| `NEBIUS_TOKEN_FACTORY_API_KEY` | *(None / Empty)* | API Key for authenticating with the Nebius Token Factory / Nebius Studio API. |
| `NEBIUS_TOKEN_FACTORY_BASE_URL` | `https://api.studio.nebius.ai/v1` | Base URL for OpenAI-compatible Nebius chat completions. |
| `NEBIUS_MODEL` | `nvidia/llama-3.1-nemotron-70b-instruct` | NVIDIA Nemotron model hosted on Nebius Token Factory. |
| `ENABLE_AI_DIAGNOSIS` | `false` | Enables the Nemotron diagnosis stage before recovery planning. |
| `NEBIUS_API_KEY` | *(None / Empty)* | Credential used by the Nemotron diagnosis client (`NEMOTRON_API_KEY` is also supported). |
| `NEBIUS_MODEL_ID` | `nvidia/nemotron-3-super-120b-a12b` | Diagnosis model (`NEMOTRON_MODEL` is also supported). |
| `ADMIN_RESET_TOKEN` | *(None / Empty)* | Optional administrative token protecting `POST /reset`. If set, resets require `X-Admin-Token` or `Authorization: Bearer`. |

Set a Nebius API key, then enable AI diagnosis if desired. The planner and diagnosis client read the same API key, base URL, model, timeout, and mock-mode configuration.

```bash
cp .env.example .env
# Set NEBIUS_API_KEY in .env; keep the key out of source control.
# Optionally opt into AI diagnosis:
ENABLE_AI_DIAGNOSIS=true uvicorn app.main:app --reload
```

When AI planning or diagnosis is unavailable, times out, or returns invalid data, the corresponding deterministic fallback is used. Recovery proposals still require approval from `DeterministicPolicyGate`; approved actions only affect the in-memory simulator.

## Environment variables

Canonical names take precedence over aliases when both are configured. The listed legacy aliases remain supported for existing shells.

| Canonical variable | Default | Supported aliases | Purpose |
|---|---|---|---|
| `NEBIUS_API_KEY` | unset | `NEMOTRON_API_KEY`, `NEBIUS_TOKEN_FACTORY_API_KEY` (legacy) | Shared Nebius credential for the planner and diagnosis client. |
| `NEBIUS_API_BASE` | `https://api.studio.nebius.ai/v1` | `NEBIUS_BASE_URL`, `NEBIUS_TOKEN_FACTORY_BASE_URL` | Shared OpenAI-compatible API base URL. |
| `NEBIUS_MODEL_ID` | `nvidia/llama-3.1-nemotron-70b-instruct` | `NEBIUS_MODEL`, `NEMOTRON_MODEL` | Shared model identifier. |
| `NEBIUS_TIMEOUT_SECONDS` | `30` | `NEMOTRON_TIMEOUT_SECONDS` | Shared request timeout; invalid values use the default. |
| `NEBIUS_MOCK_MODE` | `false` | `NEMOTRON_MOCK_MODE` | Use local diagnosis mock behavior and deterministic planner fallback. |
| `ENABLE_AI_DIAGNOSIS` | `false` | — | Opt in to the AI diagnosis stage. |
| `ADMIN_RESET_TOKEN` | unset | — | If configured, `/reset` requires the matching `X-Admin-Token` header or `Authorization: Bearer`. Missing or invalid tokens return HTTP 401. |

For local development, leaving `ADMIN_RESET_TOKEN` unset preserves the existing open simulator reset endpoint. Configure it for shared or deployed environments.

## API examples

### Submit an incident to the complete workflow

`POST /incidents` lets the existing planner create the proposal:

```bash
curl -X POST http://127.0.0.1:8000/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "web-frontend",
    "severity": "high",
    "description": "Elevated error rate and degraded service status"
  }'
```

The response includes the incident, proposed action, policy decision, simulated recovery result when approved, independent verification, final status, and audit events.

### Submit an explicitly proposed action

`POST /incidents/recover` accepts an action proposal and simulated state. The API still sends the proposal through the same deterministic policy gate:

```bash
curl -X POST http://127.0.0.1:8000/incidents/recover \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc-demo-001",
    "incident_type": "high",
    "affected_service": "web-frontend",
    "proposed_recovery_action": {
      "incident_id": "inc-demo-001",
      "action_type": "restart_service",
      "target_service": "web-frontend",
      "parameters": {},
      "safe_for_simulation": true,
      "risk_level": 1,
      "retry_count": 0
    },
    "current_system_state": {
      "service_name": "web-frontend",
      "status": "degraded",
      "cpu_percent": 45,
      "memory_percent": 50,
      "error_rate": 0.4,
      "queue_size": 0,
      "instances": 2
    }
  }'
```

Other read endpoints include `GET /health`, `GET /services`, `GET /audit`, and `GET /incidents/{incident_id}/audit`. If `ADMIN_RESET_TOKEN` is configured, reset with:

```bash
curl -X POST http://127.0.0.1:8000/reset \
  -H "X-Admin-Token: $ADMIN_RESET_TOKEN"
```

## Safety and audit guardrails

- **Policy is authoritative:** every proposed action is evaluated by `DeterministicPolicyGate`. AI cannot approve, bypass, or call the executor.
- **Simulation only:** the executor operates on in-memory infrastructure. There is no live cloud, shell, or Kubernetes execution.
- **Validated advisory output:** diagnosis and planner results are validated before use; model failures route to deterministic fallback behavior.
- **Independent verification:** post-action state is checked separately from the proposal and execution result.
- **Append-only audit:** lifecycle events are appended with a SHA-256 hash chain; `AuditLogger.verify_integrity()` checks the persisted chain. The explicit reset endpoint is the existing exception and clears simulator state and its audit history; it is authenticated when `ADMIN_RESET_TOKEN` is configured.
- **Reset protection:** `ADMIN_RESET_TOKEN`, when set, is checked using constant-time comparison. Do not put credentials in source code or commit `.env`.

## Tests and demo

```bash
pytest -q
python demo.py
```

The suite currently contains 283 tests. The demo runs five end-to-end and safety scenarios.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
