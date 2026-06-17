# 02 Domain Model

## Main building blocks

```text
Kernloom
├── Enterprise PAP: Git / PR / CI / Approval Process
├── Forge / PMS Consumer / Compiler / Publisher
├── Compiler
├── Registries
├── PIPs
├── Risk Engines
├── PDPs
├── PEPs
├── Adapters
├── Action Broker
├── Config Pipeline Integration
└── Reports
```

## Enterprise PAP: Git / PR / CI

PAP means Policy Administration Point.

For the MVP, the Enterprise PAP can be implemented as Git plus pull requests, CI checks and approvals.

Responsibilities:

- stores durable generic policy intent
- stores context model definitions
- stores risk model definitions
- stores capability registries
- stores adapter manifests and mappings
- provides version history through commits
- provides review and approval through PRs and CODEOWNERS
- runs schema validation, compile checks, Config PDP checks and report generation in CI
- is the source of truth for durable policy/config state

Git is not only storage. It is the administration workflow for durable policy truth.

## Forge / PMS Consumer

Forge is the policy compiler, publisher, control-plane orchestrator and transparency engine.

Responsibilities:

- consumes approved policy state from Git
- watches branches or releases that represent approved environments
- loads context model definitions
- loads risk model definitions
- loads capability registries
- loads adapter manifests
- invokes the compiler
- creates runtime policy packs and config deployment plans
- publishes reports
- distributes signed bundles to PDPs and adapters
- observes drift and target state

Forge does not directly make runtime allow/deny decisions.

Forge should not become a second source of truth for durable policy state. If Forge has a UI, the UI should create PRs against Git.


## Compiler

The Compiler turns generic policy intent into structured artifacts.

Input:

- policy intent
- context model
- risk model
- canonical requirements registry
- adapter capability manifests
- requirement mappings

Output:

- canonical requirements
- enforcement plan
- runtime policy pack
- config deployment plan
- delegation report
- semantic downgrade report
- coverage report

## Registries

Registries are versioned definitions used by the compiler and validators.

Required registries:

- canonical objects registry
- canonical requirements registry
- effect registry
- signal registry
- context source registry
- risk model registry
- capability registry
- requirement mapping registry
- adapter registry
- trust level registry
- action constraints registry

## Context Model

The Context Model defines what context Kernloom understands.

Examples:

- `subject.role`
- `subject.group`
- `subject.risk.level`
- `device.posture.status`
- `device.trust.level`
- `resource.application_group`
- `resource.data_class`
- `session.auth_strength`
- `session.location`
- `signal.freshness`
- `signal.confidence`

## PIP

PIP means Policy Information Point.

A PIP provides context or signals to PDPs, Risk Engines, Forge or reports.

Examples:

- IdP group membership
- MDM device compliance
- EDR health
- CMDB resource criticality
- Zscaler policy outcomes
- KLShield flow telemetry
- GeoIP
- asset inventory

PIPs are not necessarily PEPs. A system can be both, but the roles must be separated.

## Risk Engine

A Risk Engine evaluates signals and context into risk facts.

Examples:

- `subject.risk.level = high`
- `device.risk.level = medium`
- `session.risk.level = low`
- `resource.exposure.level = high`

A Risk Engine is not automatically a PDP. It creates risk assessments; PDPs make policy decisions using those assessments.

## PDP

PDP means Policy Decision Point.

Types:

- Runtime PDP
- Config PDP
- Admission PDP
- Asset PDP
- Change Proposal PDP
- Simulation PDP

Not every PDP is runtime.

## PEP

PEP means Policy Enforcement Point.

Examples:

- KLShield eBPF/XDP
- netfilter/nftables
- Envoy
- NGINX
- Zscaler runtime enforcement
- IdP token issuance
- EDR isolation
- Kubernetes admission controller
- WAF

## Adapter

An Adapter connects Kernloom to an external or local target.

Adapter roles:

- config adapter
- runtime action adapter
- telemetry/read adapter
- PIP adapter
- PEP adapter
- compiler target adapter

A vendor integration may contain multiple adapters.

Example:

```text
zscaler-integration
├── shared-api-client
├── zscaler-pip-adapter
├── zscaler-config-adapter
├── zscaler-runtime-action-adapter
├── zscaler-read-adapter
└── zscaler-requirement-mapping.yaml
```

## Vendor Sub-Control-Plane

A vendor sub-control-plane is a target that has its own policy engine, context, PDPs and enforcement.

Example: Zscaler.

Kernloom does not pretend Zscaler is a dumb PEP. Instead it records:

- what is enterprise-owned
- what is configured by Kernloom
- what is evaluated by Zscaler
- what is enforced by Zscaler
- what is vendor-native

## Action Broker

The Action Broker executes runtime decisions safely.

Responsibilities:

- route action to the correct runtime adapter
- enforce TTL
- enforce scope limits
- ensure audit logging
- ensure auto-revert
- prevent permanent config changes through runtime adapters

## Config Path

The Config Path handles durable configuration.

```text
Policy / Change Proposal
  ↓
PR / Git
  ↓
Compiler
  ↓
Config PDP
  ↓
Review / Approval
  ↓
Merge
  ↓
Config Adapter
  ↓
Target API
```

## Runtime Path

The Runtime Path handles fast temporary decisions.

```text
Runtime Event
  ↓
PIP / Signal
  ↓
Risk Engine
  ↓
Runtime PDP
  ↓
Action Broker
  ↓
Runtime Adapter / PEP
  ↓
TTL Action
```

## PAP ownership model

Kernloom distinguishes three PAP-related roles.

```text
Enterprise PAP:
  Git / PR / CI / Approval process
  Owns durable enterprise policy intent.

Forge:
  Consumes approved Git state.
  Compiles, publishes and reports.

Target PAP:
  Vendor-native admin/config plane.
  Example: Zscaler Admin API, Entra Conditional Access, Kubernetes API.
```

A vendor platform may be a Target PAP, a vendor PDP and one or more PEPs at the same time.

Example:

```text
Enterprise PAP:  Git / PR / CI
Forge:           Compiler / Publisher
Target PAP:      Zscaler Admin API
Vendor PDP:      Zscaler policy evaluation
Vendor PEP:      Zscaler enforcement fabric
```

This distinction is required for Delegation Reports and Source-of-Truth checks.
