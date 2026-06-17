# 04 Context, Risk and PIPs

## Context Model

A Context Model is the common language for all information that may influence policy or risk decisions.

It defines:

- which entities exist
- which attributes exist
- which sources may provide them
- how fresh a value must be
- how confidence is represented
- which values are canonical
- how vendor-specific facts are normalized

## Context value shape

```yaml
apiVersion: kernloom.io/v1
kind: ContextValue
metadata:
  id: ctx-123
spec:
  object: subject.risk.level
  subjectRef: user:adrian
  value: low
  source: enterprise-risk-engine
  freshness: 2m
  confidence: high
  ttl: 10m
  observedAt: "2026-06-12T12:00:00Z"
```

## Vendor assessment vs enterprise context

Vendor signals should not automatically become enterprise truth.

Example:

```yaml
vendorAssessment:
  object: vendor_signal.zscaler.user_risk
  value: high
  source: zscaler
  confidence: vendor_native
```

Then Kernloom may map it into enterprise context:

```yaml
context:
  object: subject.risk.external_assessment.zscaler
  value: high
```

A Risk Model may decide whether this affects:

```yaml
subject.risk.level: medium
```

or:

```yaml
subject.risk.level: high
```

## PIP model

PIP means Policy Information Point.

A PIP provides information to PDPs, risk engines or Forge.

PIPs can be:

- active pull sources
- event streams
- cache sources
- local sensors
- vendor telemetry sources
- inventory sources

## PIP examples

```text
IdP PIP:
  provides subject.user, subject.group, subject.role, auth events

MDM PIP:
  provides device.managed, device.compliance, device.os_version

EDR PIP:
  provides device.edr.status, device.risk.level, incident state

CMDB PIP:
  provides resource.owner, resource.criticality, resource.data_class

Zscaler PIP:
  provides policy outcomes, user risk assessment, posture outcomes

KLShield PIP:
  provides flow telemetry, packet summary, anomaly observations
```

## PIPs are not necessarily adapters to enforcement

A Zscaler integration may include:

```text
zscaler-pip-adapter:
  reads telemetry and risk/posture outcomes

zscaler-config-adapter:
  deploys durable config

zscaler-runtime-action-adapter:
  executes temporary actions if supported
```

These roles should not be hidden in one generic adapter.

## Risk Engine

A Risk Engine evaluates context and signals into risk assessments.

It may produce:

- subject risk
- device risk
- session risk
- resource risk
- application exposure risk
- tenant risk
- local flow risk

Example output:

```yaml
apiVersion: kernloom.io/v1
kind: RiskAssessment
metadata:
  id: risk-001
spec:
  object: subject.risk.level
  subjectRef: user:alice
  value: high
  confidence: medium
  ttl: 30m
  inputs:
    - zscaler.user_risk=medium
    - impossible_travel=true
    - edr.status=healthy
  owner: global-risk-engine
```

## Does every runtime PDP need a local risk engine?

No.

A runtime PDP needs access to risk/context facts, but it does not always need to calculate them locally.

Runtime PDP profiles:

```text
Profile 1: enforcement-only
  - no local PDP
  - no local risk engine
  - receives concrete actions or config

Profile 2: runtime PDP with cached context
  - makes local decisions
  - uses cached global risk/context
  - no local risk calculation

Profile 3: runtime PDP with local lightweight risk evaluator
  - local scoring for fast signals
  - can act during disconnection
  - sends findings upstream

Profile 4: runtime PDP with full local risk engine
  - advanced local correlation
  - edge autonomy
  - higher complexity
```

For KLIQ, all four profiles should be supported by capability declaration.

## What does the global risk engine do?

The global risk engine correlates broad context that local PDPs may not see.

Responsibilities:

- combine signals from many PIPs
- normalize vendor assessments
- calculate enterprise risk
- publish risk facts to PDPs
- maintain risk model versions
- explain risk assessments
- detect cross-system patterns
- create risk findings
- optionally trigger change proposals

The global risk engine should not be treated as the only PDP. It evaluates risk; PDPs decide actions using policy.

## Local vs global risk

```text
Local KLIQ risk:
  sees local flows, packets, host events, immediate anomalies
  fast, low-latency
  limited context

Global risk engine:
  sees IdP, EDR, Zscaler, CMDB, HR, MDM, tenant-wide history
  slower but richer
  better correlation
```

## Recommended design

Risk is produced as signed, versioned facts.

```text
Risk Engine → RiskAssessment → Context Store / PDP cache → Runtime PDP
```

PDPs should know:

- risk value
- source
- freshness
- confidence
- TTL
- model version

## Risk findings can create proposals

A risk finding may trigger:

- temporary runtime action
- config change proposal
- policy review proposal

But a risk engine must not directly write durable vendor configuration.

## PIP placement patterns

PIPs are placed differently depending on the target integration pattern.

### Local runtime-controlled target

For local enforcement targets such as KLIQ with KLShield or netfilter, the PIP role is usually close to the local runtime loop.

```text
Local Host / Node
  ↓
Local PIP / Signal Collector
  - packet counters
  - flow telemetry
  - conntrack state
  - local process or host facts
  ↓
Local Runtime PDP / KLIQ
  ↓
Local PEP / KLShield / netfilter
```

The PIP may be implemented by the same integration package as the PEP, but it must still be modeled as a separate logical role.

### Vendor or platform config-only target

For large platforms such as Zscaler, cloud control planes, Kubernetes clusters or IdPs, Kernloom may not be in the runtime path.

In this case the PIP is usually a read connector.

```text
Target Platform API / Logs
  ↓
Read Adapter / PIP Connector
  ↓
Context Store / Actual State Store
  ↓
Drift Engine / Report Engine / Risk Engine
```

The read connector provides actual state, telemetry and vendor assessments. It does not deploy config and it does not enforce runtime decisions.

## Actual State Facts

PIP connectors for managed platforms should emit actual state facts.

Example:

```yaml
apiVersion: kernloom.io/v1
kind: ActualStateFact
metadata:
  id: zscaler-policy-actual-001
spec:
  source: zscaler-read-adapter
  target: zscaler
  objectType: access_policy
  objectRef: allow-investors-to-investor-apps
  observedAt: "2026-06-12T12:00:00Z"
  freshness: 5m
  confidence: high
  state:
    subjectGroup: investors
    appSegmentGroup: investor-apps
    conditions:
      - zscaler_device_posture = compliant
    missingExpectedConditions:
      - zscaler_user_risk = low
```

Actual state facts are used for drift detection, reporting and optional risk findings. They should not be confused with runtime decisions.
