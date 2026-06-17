# 12 GitOps PAP Model

## Purpose

This document defines how Kernloom can use Git, pull requests, CI and approvals as the Enterprise Policy Administration Point.

The goal is to keep durable policy truth simple, auditable and reviewable.

## Decision

For the MVP:

```text
Enterprise PAP = Git + PR + CI + Approval process
Forge          = Consumer + Compiler + Publisher + Transparency Engine
PDPs           = Decision points
Adapters       = Target integrations
Vendor PAPs    = Vendor-native control planes
```

Forge does not need to be the primary policy editor.

A future Forge UI may exist, but it should create PRs instead of directly changing durable policy truth.

## Why Git can be the PAP

Git already provides many PAP properties:

- version history
- branch-based change proposals
- pull requests
- code owners
- approvals
- signed commits or tags
- CI validation
- audit trail
- rollback through commits

For policy administration, this is often better than building a custom approval workflow too early.

## What Git stores

The Git repository should store durable, reviewable artifacts:

```text
policies/
  access/
  risk/
  asset/

registries/
  canonical-objects.yaml
  canonical-requirements.yaml
  context-model.yaml
  risk-models.yaml
  capabilities/
  requirement-mappings/

adapters/
  zscaler/
  idp/
  klshield/
  netfilter/

proposals/
  optional persisted change proposals
```

Git should store enterprise intent and approved desired state, not short-lived runtime state.

## What Forge does

Forge consumes approved Git state and produces operational artifacts.

```text
Git approved branch
  ↓
Forge fetches or receives webhook
  ↓
Forge loads policies, registries and mappings
  ↓
Forge invokes compiler
  ↓
Forge publishes:
  - runtime policy packs
  - config deployment plans
  - delegation reports
  - semantic downgrade reports
  - source-of-truth reports
```

Forge is therefore a compiler and publisher, not the durable source of truth.

## Config path with Git PAP

```text
Policy Author / Change Proposal Service
  ↓
creates PR in Git
  ↓
CI validates:
  - schema
  - policy intent
  - canonical requirements
  - adapter capabilities
  - requirement mappings
  - Config PDP rules
  - delegation and downgrade reports
  ↓
Reports are attached to PR
  ↓
Review / Approval
  ↓
Merge to approved branch
  ↓
Forge consumes approved state
  ↓
Config Adapter deploys approved plan
```

## Runtime path remains separate

```text
Runtime Event
  ↓
PIP / Signal
  ↓
Risk Engine / Risk Fact
  ↓
Runtime PDP
  ↓
Action Broker
  ↓
Runtime Adapter / PEP
  ↓
TTL Action
```

Runtime must not directly write durable Git state.

Runtime may create a PR through a Change Proposal Service.

## Runtime-created config proposal

Example:

```text
Zscaler telemetry shows repeated risky access to investor-apps
  ↓
Risk Engine detects pattern
  ↓
Runtime PDP temporarily restricts affected users
  ↓
Change Proposal Service creates PR:
     - policy delta
     - config delta
     - evidence
     - delegation impact
     - downgrade impact
  ↓
CI + Config PDP validate
  ↓
Human review decides merge
```

If the proposed config enforces something not present in policy, the PR must include a policy change as well.

## Vendor PAP model

Some targets are not simple PEPs. They have their own PAP/control plane.

Example Zscaler:

```text
Enterprise PAP: Git / PR / CI
Forge:          compiler and publisher
Target PAP:     Zscaler Admin API / policy config plane
Vendor PDP:     Zscaler runtime policy evaluation
Vendor PEP:     Zscaler enforcement fabric
```

Kernloom must report this in Delegation Reports.

## Source-of-truth metadata

Every generated artifact should include source metadata.

```yaml
sourceOfTruth:
  enterprisePap: git
  repository: kernloom-policies
  branch: main
  commit: 9f3a12c
  pullRequest: 184
  approvedBy:
    - security-architecture
    - app-owner-investor-apps
  generatedBy: forge
  generatedAt: 2026-06-12T12:00:00Z
```

## Guardrails

Kernloom must reject or warn on:

- durable config plan without approved Git source
- adapter write not linked to approved commit
- Forge-side manual mutation of durable policy truth
- runtime action that writes permanent config
- vendor-side drift from approved desired state
- missing PR approval for sensitive policies

## Key sentence

Git is the Enterprise PAP for durable policy administration. Forge consumes approved Git state, compiles it, publishes artifacts and makes delegation, downgrade and drift visible.
