# 10 MVP Roadmap

## Strategic direction

Build Kernloom as a generic Policy Intent Platform first.

KLShield, netfilter and Zscaler are targets, not the architecture center.

## MVP 1: Generic policy and reports, no heavy runtime

Goal:

- define Git/PR/CI as MVP Enterprise PAP
- define generic AccessPolicy
- extract canonical requirements
- load adapter capabilities
- map requirements to targets
- produce reports

Targets:

- Zscaler as vendor sub-control-plane
- IdP as partial enforcement target
- netfilter/KLShield as local PEP example

Deliverables:

- policy intent schema
- requirement extractor
- capability manifest schema
- requirement mapping schema
- enforcement coverage report
- delegation report
- semantic downgrade report

## MVP 2: Config path for Zscaler

Goal:

- produce Zscaler deployment plan from generic policy
- validate plan through Config PDP
- create Git/PR/CI workflow as Enterprise PAP
- deploy through Zscaler Config Adapter or dry-run first

Flow:

```text
Generic AccessPolicy
  ↓
Requirements
  ↓
Zscaler Requirement Mapping
  ↓
Zscaler Deployment Plan
  ↓
Config PDP Validation
  ↓
Git / Review / Merge
  ↓
Zscaler Config Adapter
```

Important:

- runtime remains delegated to Zscaler
- risk/posture delegation is reported
- no runtime decision engine required yet for Zscaler MVP

## MVP 3: PIPs and context normalization

Goal:

- model PIPs explicitly
- import IdP groups
- import CMDB app metadata
- import Zscaler telemetry
- import KLShield flow signals
- normalize into ContextValue and VendorAssessment

Deliverables:

- PIP adapter contract
- ContextValue schema
- VendorAssessment schema
- source/freshness/confidence metadata

## MVP 4: Runtime action path for KLIQ/KLShield

Goal:

- compile runtime policy pack for KLIQ
- let KLIQ runtime PDP decide local actions
- enforce through KLShield/netfilter
- produce DecisionReceipt and EnforcementReceipt

Flow:

```text
Runtime Event
  ↓
PIP / KLShield telemetry
  ↓
Risk/context
  ↓
KLIQ Runtime PDP
  ↓
Action Broker
  ↓
KLShield / netfilter
```

## MVP 5: Change proposal bridge

Goal:

- runtime findings can create config proposals
- PR includes policy delta, config delta and evidence
- Config PDP validates proposal

Example:

```text
Runtime repeatedly sees risky access to investor-apps
  ↓
Runtime action temporarily restricts users
  ↓
Change Proposal Service creates PR:
     add device_posture requirement to investor-apps policy
  ↓
Review / Config PDP / Merge
```

## MVP 6: Adapter SDK for third parties

Goal:

- allow vendors to publish adapters
- conformance tests
- schemas for capabilities and mappings
- signed adapter manifests

## Suggested first repository modules

```text
pkg/core/intent
pkg/core/requirement
pkg/core/context
pkg/core/risk
pkg/core/capability
pkg/core/mapping
pkg/core/deploymentplan
pkg/core/report
pkg/compiler
pkg/configpdp
pkg/runtimepdp
pkg/actionbroker
pkg/pip
pkg/adapter
pkg/adapters/zscaler
pkg/adapters/idp
pkg/adapters/netfilter
pkg/adapters/klshield
```

## What to avoid in MVP

Avoid:

- building Zscaler runtime replacement
- mixing runtime actions with permanent config writes
- hiding requirement mapping in adapter code
- using only network capabilities as the canonical model
- making KLShield the source of the entire product architecture
- treating risk engine as the only PDP

## MVP acceptance criteria

The MVP is successful if it can take this policy:

```text
investors may access investor-apps only with MFA, low risk and healthy device
```

and produce:

- canonical requirements
- Zscaler target plan
- IdP target plan
- netfilter/KLShield feasibility report
- Config PDP validation
- delegation report
- semantic downgrade report

Even if actual deployment is dry-run only.

## MVP 0: GitOps PAP foundation

Goal:

- define Git as the source of truth for durable policies, registries, mappings and approved config proposals
- define PR workflow, CODEOWNERS, branch protection and CI checks
- make Forge a consumer of approved Git state, not the primary policy editor

Deliverables:

- repository layout for policies, registries, mappings and examples
- schema validation in CI
- compile dry-run in CI
- Config PDP validation in CI
- PR comments for coverage, delegation and downgrade reports
- source-of-truth metadata embedded into compiled artifacts

Flow:

```text
Policy Author or Change Proposal Service
  ↓
PR in Git
  ↓
CI: schema + compiler + Config PDP + reports
  ↓
Review / Approval
  ↓
Merge
  ↓
Forge consumes approved branch
```

## MVP 2b: Config-only target with readback and drift detection

Goal:

- support targets where Kernloom validates but does not deploy
- add read/PIP connector for actual state
- compare actual state against Git desired state
- produce Target Integration Report and Drift Report

Example target:

- Zscaler with platform-owned deployment pipeline

Flow:

```text
Git PR
  ↓
Kernloom Config PDP validates desired config
  ↓
Platform pipeline deploys to Zscaler
  ↓
Zscaler owns runtime PDP/PEP
  ↓
Zscaler Read Adapter collects actual state
  ↓
Drift Engine compares actual vs desired
  ↓
Drift Report / Change Proposal
```

Acceptance criteria:

- target can be marked `config_only_with_readback`
- no Kernloom runtime PDP is required for that target
- reports clearly show deployment owner and runtime owner
- drift detection works through read/PIP adapter
