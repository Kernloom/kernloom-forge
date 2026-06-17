# 07 Runtime Path vs Config Path

## Core rule

Kernloom may coordinate runtime and config, but it must not mix them in the same decision/deployment path.

```text
Runtime path = fast, temporary, TTL, reversible
Config path  = durable, Git/PR/CI as Enterprise PAP, review, validation, source of truth
```

## Runtime Path

Used for fast reactions.

Examples:

- block user for 30 minutes
- set user risk_state to untrusted
- isolate device temporarily
- rate-limit suspicious flow
- require step-up authentication
- deny local traffic burst

Flow:

```text
Runtime Event
  ↓
PIP / Signal Source
  ↓
Risk Engine or Risk Assessment
  ↓
Runtime PDP
  ↓
Runtime Decision
  ↓
Action Broker
  ↓
Runtime Action Adapter / PEP
  ↓
Temporary State with TTL
  ↓
Enforcement Receipt
```

## Config Path

Used for durable target configuration.

Examples:

- create Zscaler app segment
- permanently require device posture for app group
- change access policy baseline
- update IdP conditional access policy
- update Kubernetes admission policy
- deploy firewall baseline

Flow:

```text
Policy Author or Change Proposal Service
  ↓
PR in Git / Enterprise PAP
  ↓
CI runs schema validation + compiler dry-run
  ↓
Compiler creates Deployment Plan
  ↓
Config PDP validates plan
  ↓
Reports are attached to PR
  ↓
Review / Approval
  ↓
Merge
  ↓
Forge consumes approved state
  ↓
Config Adapter / Operator
  ↓
Target API
  ↓
Drift Detection
```

## Runtime can create Config Proposals

Runtime findings may reveal that a durable baseline should change.

Example:

```text
Runtime events show repeated risky access to investor-apps
  ↓
Runtime PDP temporarily restricts affected users
  ↓
Change Proposal Service creates PR:
     - policy delta
     - config delta
     - evidence
     - downgrade/delegation impact
  ↓
Config PDP validates
  ↓
Human review decides merge
```

## Important policy rule

A config proposal must include a policy basis.

If existing policy does not require device posture, but runtime proposes adding device posture to Zscaler config, then the PR must include:

- policy change
- config change
- evidence
- owner approval

Otherwise, config would enforce something that policy did not define.

## ASCII overview

```text
                    Git / PR / CI Enterprise PAP
                  Intent / Models / Governance
                              │
             ┌────────────────┴────────────────┐
             │                                 │
       Runtime Path                       Config Path
             │                                 │
   Runtime Event / Signal            Policy or Proposal
             │                                 │
   Risk Engine / Context             CI / Compiler Dry-run
             │                                 │
   Runtime PDP Decision              Config PDP
             │                                 │
   Action Broker                     Config PDP
             │                                 │
   Runtime Adapter / PEP             Review / Merge
             │                                 │
   TTL Action                        Config Adapter
             │                                 │
   Enforcement Receipt               Durable Target Config
```

## Zscaler-specific version

Initial MVP may leave Zscaler runtime mostly inside Zscaler.

```text
Config path:
  Kernloom Policy Intent
    ↓
  Zscaler Deployment Plan
    ↓
  Config PDP
    ↓
  Git / Review / Merge
    ↓
  Zscaler Config Adapter
    ↓
  Zscaler API

Runtime path:
  Zscaler runtime context
    ↓
  Zscaler risk/posture/policy evaluation
    ↓
  Zscaler enforcement
    ↓
  Zscaler telemetry back to Kernloom PIP
```

Kernloom must report this as runtime delegated.

## KLIQ-specific version

KLIQ can be controlled by Kernloom runtime packs.

```text
Forge / PMS
  ↓
Runtime Policy Pack
  ↓
KLIQ Runtime PDP
  ↓
KLShield / netfilter / local PEP
```

KLIQ may or may not have local risk capabilities.

This must be declared in KLIQ's capability manifest.

## Git as Enterprise PAP in the Config Path

The durable config path starts in Git, not in Forge.

Forge consumes approved state after merge.

```text
Policy Author / Forge UI / Change Proposal Service
  ↓
creates PR
  ↓
Git stores proposed policy/config change
  ↓
CI validates schema, requirements, capabilities and mappings
  ↓
Config PDP validates deployment plan
  ↓
Reports are attached to PR
  ↓
Human or automated approval
  ↓
Merge to approved branch
  ↓
Forge consumes approved branch
  ↓
Forge publishes signed runtime packs and config plans
```

Runtime findings may create PRs, but runtime must not directly modify durable policy truth.

## Config-only target with readback

A target can be integrated without Kernloom owning the runtime path.

This is common for large vendor platforms.

```text
Git / PR / CI
  ↓
Kernloom Config PDP validates planned config
  ↓
Platform Pipeline deploys config
  ↓
Vendor PAP / Config API
  ↓
Vendor Runtime PDP / PEP
  ↓
Read Adapter / PIP Connector
  ↓
Actual State + Telemetry back to Forge
  ↓
Drift Engine / Reports / Optional Proposals
```

In this pattern:

- Config PDP is active only during validation, simulation or reconciliation.
- The vendor Runtime PDP is continuously active for access decisions.
- The Read Adapter/PIP Connector is continuously or periodically active for state and telemetry collection.
- Kernloom may not have a Runtime PDP in the live access path.

## Drift path

Drift detection is a read-based config control loop.

```text
Desired State
  - Git
  - compiled deployment plan
  - approved config baseline
        ↓
Drift Engine compares
        ↑
Actual State
  - read by PIP/read adapter from target API
```

Result:

```text
Drift Report
  ↓
Alert / Ticket / Change Proposal / Auto-Revert if explicitly allowed
```

Drift detection must not be hidden inside a runtime action adapter.
