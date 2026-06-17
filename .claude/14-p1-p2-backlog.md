# 14 P1/P2 Backlog

Source: expert architectural review of the initial rebuild foundation.
Status: P0 items were corrected before this document was written.

## P0 — Corrected (done)

- Risk Engine and Runtime PDP separated: `riskDecisionOwner: kernloom-risk-engine`
- OpenZiti hybrid reframed as `hybrid_out_of_band` (not synchronous per-connection gate)
- `openziti-config-only` `risk_level` changed from `delegated` to `partial` (no native risk scoring)
- `IntegrationMode` field added to CapabilityManifest (required)
- `adapterRef` + `MappingKey()` added to fix manifest/mapping name coupling
- Manifests all use `kernloom-risk-engine` for riskDecisionOwner where applicable

---

## P1 — Compiler and model corrections

### P1.1: AdapterCapabilityPackage + TargetIntegrationProfile separation

Current model has one CapabilityManifest per deployment variant, leading to
duplicated manifests (openziti.yaml and openziti-config-only.yaml) that can
drift apart. Better model:

```yaml
kind: AdapterCapabilityPackage    # stable product capabilities
metadata:
  name: openziti
spec:
  roles: [vendor_pap, vendor_pdp, vendor_pep, pip_read]
  capabilities:
    - identity_role_attributes
    - service_policies
    - posture_checks
    - identity_disable

kind: TargetIntegrationProfile    # deployment-specific usage
metadata:
  name: openziti-production
spec:
  adapterPackage: openziti
  integrationMode: hybrid_out_of_band
  ownership: { ... }
```

### P1.2: Per-requirement ownership and multi-binding

Current model assigns a single owner set per target. Hybrid means some
requirements have different owners simultaneously.

Need `RequirementBinding`:
```yaml
require-low-risk:
  bindings:
    - mode: kernloom_runtime_action
      target: openziti
      role: primary_enforcement
    - mode: vendor_evaluation
      target: openziti
      role: secondary_posture_check
  composition: primary_with_compensating
```

### P1.3: enforcementConstraints on AccessPolicy

Policy must declare what forms of enforcement it accepts:

```yaml
spec:
  enforcementConstraints:
    allowDelegation: true
    allowedDelegationOwners: [openziti, idp]
    allowSemanticDowngrade: false
    minimumFidelity: high
    requireApprovalFor:
      - vendor_native_semantics
      - near_runtime_action
```

Without this, the adapter author decides that their downgrade is acceptable.
A policy saying `allowSemanticDowngrade: false` must fail compilation if any
requirement maps to `partial`.

### P1.4: Requirement-specific runtime action mapping

Currently every `runtime_action` requirement on a target receives ALL runtime
actions of that target. Need per-requirement action binding with severity tiers:

```yaml
requirementKind: risk_level
runtimeActions:
  medium:
    action: set_role_attribute
    attribute: "#kernloom-restricted"
    maxTTL: 30m
  high:
    action: disable_identity
    maxTTL: 15m
    requiresApproval: runtime_preapproved
  critical:
    action: disable_identity
    maxTTL: 5m
    requiresApproval: none
```

### P1.5: Global multi-target enforcement plan

Compiler currently asks "can this single target cover all requirements?"
The real need: "which combination of targets covers all requirements?"

```
require-low-risk
  ├─ PIP:         EDR
  ├─ PIP:         SIEM
  ├─ Risk Engine: Correlate
  ├─ PDP:         Kernloom Runtime PDP
  ├─ Action:      set OpenZiti #restricted
  └─ PEP/PDP:     OpenZiti evaluates resulting policy
```

Needs a `GlobalEnforcementPlan` type that chains PIPs → Risk Engine → PDP →
Action Broker → PEP for each requirement.

### P1.6: delegated coverage needs explicit approval

`delegated` should not be treated as equivalent to `full` in `deriveStatus`
unless the AccessPolicy explicitly approves it via `enforcementConstraints`.
Currently `delegated` is a non-gap, leading to false deployable status.

---

## P2 — Runtime safety

### P2.1: Lease model for runtime actions

```
RuntimeActionLease {
  actionID:            uuid
  targetObject:        openziti:identity:alice@example.com
  previousState:       {roleAttributes: ["#investors"]}
  desiredTempState:    {roleAttributes: ["#kernloom-restricted"]}
  startsAt:            2026-06-17T14:00:00Z
  expiresAt:           2026-06-17T14:30:00Z
  owner:               kernloom-runtime-pdp
  fencingToken:        abc123
  reconciliationStatus: active
}
```

### P2.2: TTL Reconciler

Background process that:
- lists active leases
- checks expiry
- calls revert action on the target adapter
- handles adapter failures (retry with backoff)
- detects and handles concurrent manual changes (fencing token)

### P2.3: Monotonic restriction invariant enforcement

Code-level invariant: runtime actions must only REDUCE access, never grant it.

- Validate in adapter interface that action is classified as `restrictive`
- Reject any action that could widen access
- Log and alert on any action that modifies a deny → allow

### P2.4: Action receipts

Every runtime action produces a `RuntimeActionReceipt`:
- action ID, target, requirement, policy
- decision owner, enforcement owner
- started, expires, reverted timestamps
- reconciliation status

Replaces the current `autoRevert: true` assertion with an auditable record.

### P2.5: Conflict and failure handling

- What happens if two Kernloom instances both try to modify the same identity?
- What happens if the target API is unavailable during TTL expiry revert?
- What happens if a manual admin change conflicts with an active lease?
- What happens if Forge/Broker crashes with active leases?

---

## Notes on the repository state

The rebuild deleted ~12,594 lines from the PoC (`poc-v1` tag preserves them).
The signing module was intentionally kept. Old registry, forge API, DB, pack
renderer, validators and KLIQ-specific tests were removed as part of the
rebase onto the generic intent platform model.

Before building further production-grade features:
- P1.3 (enforcementConstraints) must be in place before any live deployment
- P2.1-P2.2 (Lease + Reconciler) must be in place before any vendor target
  receives runtime actions in production
