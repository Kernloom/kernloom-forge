# 05 PDP, PEP, PIP and Adapter Model

## Definitions

## PAP

Policy Administration Point.

In the MVP, the Enterprise PAP is Git plus PR, CI and approval workflow.

```text
Git / PR / CI:
  administers durable policy intent
  versions changes
  runs validation
  records approval
  is the source of truth
```

## PMS / Forge

Forge consumes approved policy state from the Enterprise PAP.

Forge compiles, publishes, distributes and reports.

Forge does not directly decide runtime access and must not silently become a second source of truth.


## PDP

Policy Decision Point.

A PDP makes a decision in a specific context.

Types:

```text
Runtime PDP:
  decides now, usually with live context

Config PDP:
  validates whether durable config may be deployed

Admission PDP:
  decides whether an object may enter a platform, e.g. Kubernetes admission

Asset PDP:
  validates assets before deployment, e.g. image, IaC, cloud config

Change Proposal PDP:
  decides whether a proposed config/policy change is valid enough to enter review

Simulation PDP:
  evaluates hypothetical decisions for planning and what-if analysis
```

Not every PDP is runtime.

## PEP

Policy Enforcement Point.

A PEP enforces a decision or policy.

Examples:

- KLShield
- netfilter
- nftables
- Envoy
- NGINX
- IdP token issuance
- Zscaler enforcement
- EDR isolation
- Kubernetes admission
- WAF

## PIP

Policy Information Point.

A PIP provides context or signals.

Examples:

- IdP
- MDM
- EDR
- CMDB
- Zscaler telemetry
- KLShield telemetry
- GeoIP
- asset inventory

## Adapter

An adapter is a software integration implementing one or more roles:

```text
PIP adapter:
  reads context/signals

Config adapter:
  writes durable config

Runtime action adapter:
  executes temporary runtime actions

PEP adapter:
  connects a PDP to an enforcement point

Compiler target adapter:
  provides mapping and target plan schemas
```

A single vendor integration may contain multiple adapters.

## Adapter modes

Each adapter must declare supported modes.

```yaml
apiVersion: kernloom.io/v1
kind: AdapterManifest
metadata:
  name: zscaler
spec:
  modes:
    - pip_read
    - config_write
    - runtime_delegated
    - telemetry_read
  targetType: vendor_sub_control_plane
```

## Runtime PDP profiles

A runtime PDP can be deployed with different levels of autonomy.

```yaml
apiVersion: kernloom.io/v1
kind: RuntimePDPProfile
metadata:
  name: kliq-edge-lite
spec:
  riskEngineMode: none
  contextMode: cached
  decisionMode: local
  offlineBehavior: fail_closed_for_sensitive_resources
  allowedActions:
    - rate_limit
    - deny_flow
    - require_step_up
```

Other possible risk engine modes:

```text
none
cached_global
local_lite
local_full
hybrid
```

## PDP+ control

Kernloom should be able to control known PDPs and PDP-like systems.

Examples:

- KLIQ local runtime PDP
- Correlate global runtime PDP
- Config PDP
- Kubernetes admission PDP
- IdP conditional access PDP
- Zscaler vendor PDP
- WAF policy engine
- EDR response engine

But Kernloom must distinguish between:

- PDP owned by Kernloom
- PDP configured by Kernloom
- PDP observed by Kernloom
- PDP delegated to vendor

## Ownership model

Every compiled target should declare:

```text
Intent Owner
Context Owner
Risk Decision Owner
Runtime Decision Owner
Policy Evaluation Owner
Enforcement Owner
Config Owner
State Owner
```

Example Zscaler runtime delegated:

```yaml
ownership:
  intentOwner: enterprise-pms
  runtimeContextOwner: zscaler
  riskDecisionOwner: zscaler
  runtimeDecisionOwner: zscaler
  policyEvaluationOwner: zscaler
  enforcementOwner: zscaler
  configOwner: git/config-pipeline
```

Example KLIQ local PDP:

```yaml
ownership:
  intentOwner: enterprise-pms
  runtimeContextOwner: kliq/local-pips
  riskDecisionOwner: local-risk-engine-or-global-risk-cache
  runtimeDecisionOwner: kliq-runtime-pdp
  policyEvaluationOwner: kliq-runtime-pdp
  enforcementOwner: klshield
  configOwner: forge/runtime-bundle
```

## Important anti-pattern

Do not use one generic `adapter` abstraction for everything.

This hides whether the adapter is:

- reading signals
- making decisions
- deploying config
- enforcing runtime action
- validating config
- delegating to a vendor PDP

Instead, model roles explicitly.

## Target integration patterns

A tool does not have to be both PIP and PEP.

Each integration declares which roles it provides.

```text
Tool / Platform
  may provide:
    - PIP role: read context, telemetry, actual state
    - PAP role: manage durable policy/config through API
    - PDP role: make decisions
    - PEP role: enforce decisions
```

### Pattern A: Local runtime-controlled target

Example: KLIQ + KLShield.

```text
Local PIP → Kernloom Runtime PDP → Local PEP
```

Ownership:

```yaml
pattern: local_runtime_controlled
roles:
  pip: local-signal-collector
  pdp: kliq-runtime-pdp
  pep: klshield
  pap: forge-runtime-bundle-publication
runtimeOwner: kernloom
configOwner: forge-runtime-bundle
```

### Pattern B: Vendor config-only target

Example: Zscaler MVP where runtime remains in Zscaler.

```text
Git / PR → Config PDP Validation → Platform Deploy → Vendor PAP/API
                                                    ↓
                                             Vendor PDP / PEP
                                                    ↓
                                             Read Adapter / PIP
```

Ownership:

```yaml
pattern: vendor_config_only
roles:
  pap: vendor-admin-api
  pdp: vendor-runtime-pdp
  pep: vendor-enforcement
  pip: read-adapter
runtimeOwner: vendor
validationOwner: kernloom-config-pdp
configDeployOwner: platform-pipeline
```

### Pattern C: External platform deploy with Kernloom validation only

Some platform teams may write and own their own deployment adapter.

Kernloom validates the planned change, but the deployment execution is external.

```text
PR / Plan
  ↓
Kernloom Config PDP Check
  ↓
Required PR / Pipeline Check
  ↓
Platform-owned Deploy Adapter
  ↓
Target System
```

Kernloom must report that it validated the plan but did not own deployment.

## Integration role matrix

```text
CMDB:       PIP only
Terraform:  Plan source / asset input, not PIP/PEP by itself
Netfilter:  PEP, optional local counters as PIP
KLShield:   PEP + local telemetry PIP
IdP:        PAP + PDP + PEP + PIP, depending on integration
Zscaler:    Vendor PAP + Vendor PDP + PEP + PIP/read source
EDR:        PIP + PEP/runtime-action target + PAP/config API
Kubernetes: PAP + Admission PDP + PEP + PIP/read source
```

## Config-only targets do not require a Kernloom runtime PDP

If runtime is delegated to a vendor platform, there may be no continuously active Kernloom Runtime PDP for that target.

Kernloom still provides:

- Config PDP validation during PR/CI
- capability and requirement mapping
- delegation reports
- semantic downgrade reports
- read/PIP connector for telemetry and actual state
- drift detection
- optional change proposals

This is valid and should be explicitly modeled as `runtime_delegated` or `config_only_with_readback`.
