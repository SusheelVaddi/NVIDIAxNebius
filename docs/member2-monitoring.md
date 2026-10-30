# Autonomous IT Reliability & Incident Recovery System
## Member 2: Monitoring & Deterministic Incident Detection

Autonomous infrastructure monitoring and deterministic incident detection engine for the **NVIDIA × Nebius Global AI Hackathon**.

---

## 1. Project Overview & Workflow

This project implements an autonomous closed-loop reliability and recovery framework structured around the following operational lifecycle:

$$\text{Detect} \longrightarrow \text{Diagnose} \longrightarrow \text{Decide} \longrightarrow \text{Execute} \longrightarrow \text{Verify} \longrightarrow \text{Replan}$$

1. **Detect:** Ingests infrastructure telemetry windows, performs deterministic threshold checks against configured service limits, and emits structured `IncidentPayload` events.
2. **Diagnose:** Consumes `IncidentPayload` context (metrics, logs, deployment events) to infer the root cause via Nemotron AI Diagnosis.
3. **Decide:** Evaluates proposed actions against deterministic safety policies; AI recommendations are advisory only.
4. **Execute:** Runs approved recovery actions against the in-memory infrastructure simulator.
5. **Verify:** Independently checks the simulated post-recovery state.

---

## 2. Component Boundaries

`src/monitoring` provides telemetry modeling, deterministic scenarios, threshold-based detection, evidence collection, and severity classification. The recovery API and orchestration are implemented under `app/`. The detector does not invoke recovery actions or mutate simulated infrastructure.

---

## 3. Directory Structure

This local workspace contains only verified Member 2 files and shared contract definitions:

```text
E:\Projects\NVIDIAxNebius\
├── README.md                          # Project & module documentation
├── src\
│   ├── __init__.py                    # Source package marker
│   ├── schemas.py                     # Shared cross-member Pydantic contracts
│   └── monitoring\
│       ├── __init__.py                # Monitoring module public API
│       ├── config.py                  # MonitoringConfig threshold definitions
│       ├── detector.py                # Deterministic threshold detection engine
│       ├── scenarios.py               # Deterministic synthetic scenario generators
│       └── telemetry.py               # TelemetryWindow & Telemetry containers
└── tests\
    ├── __init__.py                    # Test package marker
    └── test_monitoring.py            # Complete unittest test suite (40 tests)
```

---

## 4. Shared Schemas Overview (`src.schemas`)

Defined in `src/schemas.py` and shared across all three members:

- **`IncidentSeverity` (Enum):** Severity classification: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- **`MetricSnapshot` (BaseModel, frozen):** Immutable snapshot of telemetry metrics at a point in time:
  - `latency_p50_ms` ($\ge 0.0$)
  - `latency_p99_ms` ($\ge 0.0$)
  - `error_rate_pct` ($0.0 \le x \le 100.0$)
  - `request_rate_rps` ($\ge 0.0$)
  - `cpu_utilization_pct` ($0.0 \le x \le 100.0$)
  - `memory_utilization_pct` ($0.0 \le x \le 100.0$)
- **`LogEntry` (BaseModel, frozen):** Structured log line containing `timestamp`, `level` (`INFO`, `WARN`, `ERROR`, `FATAL`, `DEBUG`), `message`, optional `component`, and optional `trace_id`.
- **`EvidenceItem` (BaseModel, frozen):** Specific rule breach details containing `rule_id`, `metric_name`, `threshold_value`, `observed_value`, and human-readable `explanation`.
- **`DeploymentEvent` (BaseModel, frozen):** Details of a recent software rollout: `deployment_id`, `service`, `version`, `deployed_at`, and `status`.
- **`IncidentPayload` (BaseModel, frozen, alias `Incident`):** Complete structured payload emitted upon breach:
  - `incident_id`: Deterministic unique identifier (`INC-{service}-{YYYYMMDDHHMMSSffffff}`).
  - `service`: Target service name.
  - `timestamp`: Telemetry window timestamp.
  - `severity`: Classified `IncidentSeverity`.
  - `summary`: Concise incident summary with breach count.
  - `metrics`: Observed `MetricSnapshot`.
  - `logs`: Relevant contextual `List[LogEntry]`.
  - `evidence`: `List[EvidenceItem]` detailing all violated rules.
  - `recent_deployment`: Optional `DeploymentEvent` associated with the incident window.

---

## 5. Monitoring Module Overview (`src.monitoring`)

- **`MonitoringConfig` (`src/monitoring/config.py`):** Frozen dataclass storing detection thresholds and default service name.
- **`TelemetryWindow` (`src/monitoring/telemetry.py`):** Container for windowed telemetry with `service`, `timestamp`, `metrics`, `logs`, optional `recent_deployment`, and `service_status`.
- **`generate_healthy_scenario(service=None, seed=42, base_time=None)` (`src/monitoring/scenarios.py`):** Produces a fully deterministic baseline telemetry window with healthy metrics, clean INFO logs, and no anomalies.
- **`generate_faulty_deployment_scenario(service=None, seed=42, base_time=None)` (`src/monitoring/scenarios.py`):** Produces a deterministic degraded scenario simulating a connection pool leak following deployment of `v2.4.1`, complete with elevated latency, critical error rate, exhausted pool error logs, and `recent_deployment` metadata.
- **`detect_incident(telemetry, config=None)` (`src/monitoring/detector.py`):** Evaluates a `TelemetryWindow` against threshold rules. Returns an `IncidentPayload` if any rule is breached, or `None` if healthy.

---

## 6. Thresholds & Severity Precedence

### Default Thresholds (`MonitoringConfig`)

| Metric | Warning Threshold (`warn`) | Critical Threshold (`crit`) |
|---|---|---|
| **p99 Latency** | `500.0 ms` | `1200.0 ms` |
| **Error Rate** | `2.0 %` | `8.0 %` |
| **CPU Utilization** | `80.0 %` | `90.0 %` |
| **Memory Utilization** | `85.0 %` | `95.0 %` |

*Threshold comparisons are inclusive ($\ge$). Service status is normalized with whitespace stripping and case-insensitivity before comparison.*

### Severity Precedence Hierarchy

The detection engine classifies incident severity deterministically using strict precedence rules:

1. **Step 1: CRITICAL**
   - Error rate critical breach ($\ge 8.0\%$), **OR**
   - Dual warning breach: error rate warning ($\ge 2.0\%$) **AND** p99 latency warning ($\ge 500.0\text{ ms}$) simultaneously, **OR**
   - Service status explicitly normalized to `"UNHEALTHY"`.
2. **Step 2: HIGH**
   - Critical p99 latency breach ($\ge 1200.0\text{ ms}$), **OR**
   - Warning error rate breach ($\ge 2.0\%$), **OR**
   - Critical CPU utilization breach ($\ge 90.0\%$), **OR**
   - Critical memory utilization breach ($\ge 95.0\%$).
3. **Step 3: MEDIUM**
   - Any remaining single warning breach (p99 latency $\ge 500.0\text{ ms}$, CPU $\ge 80.0\%$, memory $\ge 85.0\%$, or service status normalized to `"DEGRADED"`).

> [!NOTE]
> - `IncidentSeverity.LOW` exists in `src/schemas.py` as a supported enum value.
> - The current `detect_incident()` implementation does not emit `LOW`.
> - Detected incidents are classified as `CRITICAL`, `HIGH`, or `MEDIUM`.
> - If no threshold or status rule is breached, `detect_incident()` returns `None`.

---

## 7. Python Usage Example

```python
from datetime import datetime, timezone
from src.monitoring import (
    MonitoringConfig,
    generate_faulty_deployment_scenario,
    generate_healthy_scenario,
    detect_incident,
)

# 1. Initialize configuration (or customize thresholds)
config = MonitoringConfig()

# 2. Generate simulated telemetry (100% deterministic with seed)
telemetry = generate_faulty_deployment_scenario(seed=42)

# 3. Detect incidents deterministically (returns IncidentPayload or None)
incident = detect_incident(telemetry, config=config)

# 4. Safely handle the result
if incident is not None:
    print(f"Incident ID : {incident.incident_id}")
    print(f"Service     : {incident.service}")
    print(f"Severity    : {incident.severity.value}")
    print(f"Summary     : {incident.summary}")
    print(f"Breaches    : {len(incident.evidence)} rule(s) violated")
    for ev in incident.evidence:
        print(f"  - [{ev.rule_id}] {ev.metric_name}: observed {ev.observed_value} >= threshold {ev.threshold_value}")
    if incident.recent_deployment:
        print(f"Deployment  : {incident.recent_deployment.version} ({incident.recent_deployment.deployment_id})")
else:
    print("Telemetry is healthy. No incident detected.")
```

---

## 8. Deterministic Guarantees & Safety

- **Deterministic Logic:** The detection engine is pure code logic. Given identical inputs, it always produces identical incident IDs, evidence lists, and severity classifications.
- **RNG Isolation:** Scenario generators instantiate a dedicated `random.Random(seed)` instance, preventing side-effects on global random state.
- **No AI / LLM Calls:** Monitoring code does **not** call any LLM, AI model, or external service.
- **No Side-Effects or Execution:** The detector does **not** invoke recovery actions, mutate system state, or execute shell commands. Recovery orchestration belongs to `app/`.

---

## 9. Known Limitations

- **Zero-Traffic Blackholes:** If a service has `request_rate_rps = 0.0` with `error_rate_pct = 0.0` and healthy status, the detector currently returns `None`. Because thresholds are upper bounds and baseline expected request volumes vary per service, an idle service cannot be differentiated from a complete ingress blackhole without an agreed baseline traffic model.

---

## 10. Integration Notes

- **For Nemotron AI diagnosis:**
  - Ingest `IncidentPayload` directly from `detect_incident()`.
  - Check `incident.recent_deployment` for structured deployment context (`version`, `deployment_id`) to diagnose faulty releases without scraping unstructured log strings.
  - Access structured violations via `incident.evidence`.
- **For recovery orchestration:**
  - AI diagnosis is advisory; validate proposed actions against policy checks before execution.
  - Inspect `incident.recent_deployment.version` to determine rollback targets.
  - Use `generate_healthy_scenario()` and `generate_faulty_deployment_scenario()` for integration testing and post-recovery verification loops.

---

## 11. Running Tests

Run the complete unit test suite using Python's built-in `unittest` runner (zero external dependencies required):

```powershell
python -m unittest discover -s tests -v
```

All 40 unit tests cover baseline health, faulty rollouts, exact boundaries, below-threshold conditions, CPU/memory thresholds, service status normalization, custom configs, severity precedence, zero traffic, and microsecond ID collision resistance.
