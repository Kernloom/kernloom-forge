# Kernloom Agent Brief

## Purpose

This document set describes Kernloom as a generic Policy Intent Platform for Zero Trust and security control orchestration.

Kernloom must not be designed only for KLShield. KLShield is one enforcement target among many. Kernloom must become a vendor-neutral platform that can express security intent once, map it to multiple targets, and make transparent what is fully enforced, partially enforced, delegated, downgraded, or not enforceable.

## Core idea

Kernloom separates five concerns:

- Policy intent: what the enterprise wants to be true.
- Context and risk: what is known about subjects, devices, resources, sessions and signals.
- Decision making: where a PDP decides something.
- Enforcement: where a PEP or vendor sub-control-plane enforces something.
- Transparency: what was preserved, delegated, downgraded or lost during translation.

## Main design correction if rebuilt from scratch

If Kernloom were rebuilt from scratch, the architecture should start with the generic PMS model first, and only then derive KLShield, KLIQ, Zscaler, IdP, EDR, Firewall, WAF and other adapters.

Do not start with local network enforcement and later generalize it. Start with:

```text
Enterprise Policy Intent
  ↓
Canonical Requirements
  ↓
Capability Matching
  ↓
Requirement Mapping
  ↓
Target Plans
  ↓
PDP Validation / Runtime Decisions
  ↓
Adapters / PEPs / Vendor Sub-Control-Planes
  ↓
Delegation and Downgrade Reports
```

## What Kernloom is

Kernloom is:

- an Enterprise Policy Management System
- a GitOps-oriented Enterprise PAP model where Git/PR/CI can be the policy administration source of truth
- a Policy Intent model
- a Compiler and Translation system
- a Capability and Requirement Mapping platform
- a PDP coordination layer
- an Adapter SDK and registry
- a transparency/reporting system for delegation and semantic downgrade
- a bridge between runtime actions and long-lived configuration changes

## What Kernloom is not

Kernloom is not:

- only an eBPF or netfilter product
- only a local firewall manager
- only a Zscaler automation wrapper
- only a policy UI
- a system that silently removes non-enforceable policy conditions
- a system that lets runtime events directly create permanent config without review

## Required engineering behavior for an AI coding agent

When implementing Kernloom, always preserve these invariants:

1. Policy intent is vendor-neutral.
2. Adapters do not define enterprise semantics.
3. Requirement mapping must be explicit and versioned.
4. Capability matching must happen before target-specific deployment.
5. Git/PR/CI may act as the Enterprise PAP and source of truth for durable policy administration.
6. Forge consumes approved Git state; it must not silently become a competing source of truth.
7. Runtime path and config path are separate.
8. Runtime may create config proposals, but must not directly mutate durable policy/config state.
9. Every target plan must produce coverage, delegation and downgrade information.
10. PIPs are first-class context/signal providers, not hidden inside PEP adapters.
11. Not every PDP is runtime.
12. Not every runtime PDP needs a local risk engine.

13. Not every target is both PIP and PEP; target roles must be declared explicitly.
14. Config-only vendor targets may have no Kernloom Runtime PDP; use read/PIP connectors for drift and transparency.

## Minimal document reading order

1. `01-architecture-principles.md`
2. `02-domain-model.md`
3. `03-policy-intent-and-requirements.md`
4. `04-context-risk-and-pips.md`
5. `05-pdp-pep-pip-adapter-model.md`
6. `06-capability-and-requirement-mapping.md`
7. `07-runtime-vs-config-path.md`
8. `08-reports-and-transparency.md`
9. `09-adapter-sdk-and-vendor-model.md`
10. `10-mvp-roadmap.md`
11. `11-ai-implementation-backlog.md`
12. `12-gitops-pap-model.md`
13. `13-target-integration-patterns.md`

Diagrams:

- `architecture-overview.txt`
- `gitops-pap-flow.txt`
- `runtime-config-separation.txt`
- `vendor-sub-control-plane.txt`
- `target-integration-modes.txt`
- `drift-detection-flow.txt`
