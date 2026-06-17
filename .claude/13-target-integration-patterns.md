# 13 Target Integration Patterns and Drift Model

## Purpose

This document defines how Kernloom integrates different target systems without assuming every target is both a PIP and a PEP.

Kernloom must support local runtime-controlled targets, large vendor sub-control-planes, read-only information sources, and external platform deploy pipelines.

## Core rule

A tool is not automatically a PIP and a PEP.

A tool or platform may provide any combination of:

- PIP: provides context, signals, telemetry or actual state
- PAP: manages durable policies or configuration
- PDP: makes decisions
- PEP: enforces decisions

The adapter manifest must declare these roles explicitly.

## Pattern 1: Local runtime-controlled target

Use when Kernloom owns the local runtime decision loop.

Example:

- KLIQ local runtime PDP
- KLShield or netfilter local PEP
- local packet/flow telemetry as PIP

```text
Local Host / Node

Local PIP / Signal Collector
  ↓
Local Runtime PDP / KLIQ
  ↓
Local PEP / KLShield / netfilter
  ↓
Temporary enforcement with receipt
```

Characteristics:

- Kernloom is active in the runtime path.
- Decisions are fast and local.
- Actions should have TTL where appropriate.
- PIP/PDP/PEP may be packaged together but must be modeled separately.

Ownership example:

```yaml
pattern: local_runtime_controlled
roles:
  pip: local-flow-collector
  pdp: kliq-runtime-pdp
  pep: klshield
runtimeOwner: kernloom
riskMode: cached_global_or_local_lite
```

## Pattern 2: Vendor config-only with readback

Use when Kernloom validates durable configuration but the vendor owns runtime decisions.

Example:

- Zscaler MVP
- Vendor runtime remains inside Zscaler
- Kernloom reads telemetry and actual state for drift/transparency

```text
Git / PR / CI Enterprise PAP
  ↓
Kernloom Config PDP validates plan
  ↓
Platform Deploy Pipeline
  ↓
Vendor PAP / Config API
  ↓
Vendor Runtime PDP / PEP
  ↓
Read Adapter / PIP Connector
  ↓
Forge State Store / Drift Engine / Reports
```

Characteristics:

- Kernloom may not deploy config itself.
- Kernloom may not own runtime decisions.
- A continuously active Kernloom runtime PDP is not required for this target.
- A read/PIP connector is still valuable for drift, telemetry and reporting.

Ownership example:

```yaml
pattern: vendor_config_only_with_readback
roles:
  pap: zscaler-admin-api
  pdp: zscaler-runtime-pdp
  pep: zscaler-enforcement
  pip: zscaler-read-adapter
validationOwner: kernloom-config-pdp
deploymentOwner: platform-pipeline
runtimeOwner: zscaler
```

## Pattern 3: External platform deploy with Kernloom validation only

Use when a platform team owns deployment adapters and credentials.

```text
PR / Terraform Plan / Target Config
  ↓
Kernloom Config PDP check
  ↓
Required CI status
  ↓
Platform-owned deploy adapter
  ↓
Target system
```

Characteristics:

- Kernloom validates the plan.
- Deployment is external.
- Bypass prevention depends on Git protection, required checks and credential separation.
- Drift detection is required to detect out-of-band changes.

## Pattern 4: Read-only PIP target

Use when a system only provides context.

Examples:

- CMDB
- HR directory
- asset inventory
- vulnerability scanner

```text
Read Adapter / PIP Connector
  ↓
ContextValue / ActualStateFact / VendorAssessment
  ↓
Forge Context Store
```

No PEP or PDP is required.

## Pattern 5: Vendor sub-control-plane with optional runtime action

Use when Kernloom can execute constrained temporary actions through a vendor platform.

```text
Runtime Finding
  ↓
Runtime PDP
  ↓
Action Broker
  ↓
Vendor Runtime Action Adapter
  ↓
Temporary vendor-side action with TTL
```

This is not the same as durable config deployment.

Constraints:

- TTL required
- audit required
- auto-revert required where possible
- no permanent access-policy mutation
- action constraints must be declared in the adapter package

## Drift detection placement

Drift detection belongs to the config/observability path, not the runtime action path.

```text
Desired State
  - Git
  - approved deployment plan
  - compiled target baseline
        ↓
      compare
        ↑
Actual State
  - target API
  - read adapter / PIP connector
  - telemetry export
```

Output:

```text
Drift Report
  ↓
Alert / Ticket / Change Proposal / Optional Auto-Revert
```

## Zscaler MVP example

```text
Git as Enterprise PAP
  ↓
Config PDP validates Zscaler desired state
  ↓
Platform pipeline deploys to Zscaler
  ↓
Zscaler owns runtime PDP and PEP
  ↓
Zscaler Read Adapter collects actual policies and outcomes
  ↓
Kernloom Drift Engine compares actual vs desired
  ↓
Reports show delegation, downgrade and drift
```

No Kernloom runtime PDP is required for Zscaler in this MVP.

## Reporting requirements

Every target integration must produce a Target Integration Report.

Minimum fields:

```yaml
target: zscaler
pattern: vendor_config_only_with_readback
roles:
  pip: zscaler-read-adapter
  pap: zscaler-admin-api
  pdp: zscaler-runtime-pdp
  pep: zscaler-enforcement
owners:
  validation: kernloom-config-pdp
  deployment: platform-pipeline
  runtime: zscaler
  desiredState: git-enterprise-pap
  actualState: zscaler-read-adapter
```

## Design invariant

Do not force every integration into the same shape.

Kernloom must model what a target actually does:

- read only
- config only
- runtime only
- config plus readback
- local runtime controlled
- vendor runtime delegated
- external deploy with validation only

Transparency is more important than pretending that Kernloom owns every decision and every deployment.
