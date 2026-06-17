# Kernloom Forge

Forge is the policy governance and compilation plane for the [Kernloom](https://kernloom.com) Zero Trust platform. It translates vendor-neutral enterprise policy intent into enforcement plans, signed runtime bundles, and transparency reports.

Forge does not enforce anything itself. It compiles, signs, and distributes.
KLIQ enforces locally via its PEP adapters (KLShield, netfilter, OpenZiti, …).

---

## Core idea

Forge separates five concerns:

```
Enterprise Policy Intent (Git/PAP)
    ↓
Canonical Requirements
    ↓
Capability Matching per Target
    ↓
Enforcement Plan → Delegation/Downgrade/Coverage Reports
    ↓
RuntimeBundle (signed) → KLIQ Runtime PDP
```

A policy written once compiles against multiple targets simultaneously. Each target declares what it can enforce, where it delegates, and where enforcement is compensated via runtime actions.

---

## Current state

| Package | Description | Status |
|---|---|---|
| `pkg/core/intent/` | AccessPolicy schema, PolicyEnvelope, multi-kind dispatch | ✅ |
| `pkg/core/requirement/` | RequirementSet, extractor, CEL + structured conditions | ✅ |
| `pkg/core/adapter/` | AdapterCapabilityManifest — product-level capabilities | ✅ |
| `pkg/core/profile/` | TargetIntegrationProfile — deployment-specific integration | ✅ |
| `pkg/core/mapping/` | RequirementMappingSet — canonical → adapter translation | ✅ |
| `pkg/core/action/` | RuntimeActionCatalog — TTL-bounded restrictive actions | ✅ |
| `pkg/core/plan/` | EnforcementPlan — compiler governance output | ✅ |
| `pkg/core/context/` | ContextFact, VendorAssessment, ContextSnapshot, Registry | ✅ |
| `pkg/core/risk/` | RiskAssessment, RiskModel, deterministic Risk Engine | ✅ |
| `pkg/core/bundle/` | RuntimeBundle, RuntimePolicyPack, RuntimePDPProfile | ✅ |
| `pkg/bundler/` | Build + Sign + Verify (Ed25519) | ✅ |
| `pkg/compiler/` | AccessPolicy → EnforcementPlan | ✅ |
| `registries/context/` | Canonical context key definitions | ✅ |
| `registries/risk/` | Reference risk model (enterprise-access-risk) | ✅ |
| Forge Control Plane API | Node enrollment, bundle distribution, findings reception | planned |
| Config PDP | Validates EnforcementPlan against enforcementConstraints | planned |
| Drift Detection | Read connector + actual state comparison | planned |

---

## Quick start

```bash
# Build
export PATH=$PATH:/usr/local/go/bin
go build -o bin/forge ./cmd/forge/

# Run tests
go test ./...

# Compile a policy against adapter profiles
./bin/forge compile \
  --policy  examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/

# Validate a policy
./bin/forge validate --policy examples/policies/investor-apps-access.yaml

# Validate an adapter capability manifest
./bin/forge validate-adapter --adapter examples/adapters/openziti/capability.yaml
```

---

## Key concepts

### AccessPolicy — vendor-neutral intent

```yaml
apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: investor-apps-access
spec:
  subject:
    type: role
    ref: investors
  resource:
    type: application_group
    ref: investor-apps
  conditions:
    - id: require-mfa
      type: authentication_strength
      cel: "subject.auth_strength >= 'mfa'"
    - id: require-low-risk
      type: risk_level
      signal: subject.risk.level
      operator: eq
      value: low
  effect: allow
```

Conditions support both CEL expressions and structured `signal/operator/value` format.

### Five-object adapter model

| Object | Location | Purpose |
|---|---|---|
| `AdapterCapabilityManifest` | `examples/adapters/<vendor>/capability.yaml` | What the product can do (stable) |
| `TargetIntegrationProfile` | `examples/profiles/<name>.yaml` | How this deployment uses the adapter |
| `RequirementMappingSet` | `examples/adapters/<vendor>/mappings.yaml` | How requirements translate to capabilities |
| `RuntimeActionCatalog` | `examples/adapters/<vendor>/actions.yaml` | TTL-bounded restrictive actions |
| `EnforcementPlan` | compiler output | Governance report: coverage, delegation, downgrades |

### Integration modes

| Mode | Description |
|---|---|
| `config_only` | Forge writes durable config; vendor owns all runtime |
| `enterprise_risk_overlay` | Vendor owns runtime auth; Kernloom issues out-of-band TTL restrictions |
| `kernloom_pdp_native` | Kernloom Runtime PDP is the in-path decision point |

### Compensating controls

When a vendor cannot evaluate an enterprise requirement natively (e.g. OpenZiti has no risk scoring), Forge maps it as `compensating_control`. The compiler generates a RuntimePolicy CEL rule that KLIQ evaluates locally:

```yaml
# In RequirementMappingSet:
- requirement:
    kind: risk_level
  support: compensating_control
  binding:
    riskAssessmentOwner: kernloom-risk-engine
    decisionOwner: kernloom-runtime-pdp
    action: remove_kernloom_access_attribute
    attribute: kl.access.active
```

```yaml
# In compiled RuntimePolicyPack:
- id: compensating-risk_level-openziti
  when:
    language: cel
    expression: "risk.level in ['high','critical'] && risk.confidence >= 0.80"
  effect:
    capability: access.restrict.identity
    ttl: 30m
```

### Context and Risk

```yaml
# registries/context/canonical-keys.yaml
# 25 canonical context keys: subject.role, device.posture.status,
# session.authentication.strength, subject.risk.level, ...

# registries/risk/enterprise-access-risk-v1.yaml
# Deterministic CEL-based risk model: vendor-neutral rules,
# per-domain scoring, exponential decay, negative contributions
```

The risk engine is a pure function: `Evaluate(model, snapshot, indicators) → EvalResult`. Used for Forge simulation/validation, KLIQ local evaluation, and Correlate global aggregation.

---

## Repository layout

```
kernloom-forge/
├── cmd/forge/                     CLI entry point (compile, validate, validate-adapter)
├── examples/
│   ├── adapters/
│   │   ├── openziti/              capability.yaml, mappings.yaml, actions.yaml
│   │   ├── idp/                   capability.yaml, mappings.yaml
│   │   ├── klshield/              capability.yaml, mappings.yaml, actions.yaml
│   │   └── netfilter/             capability.yaml, mappings.yaml
│   ├── profiles/                  openziti-production.yaml, openziti-config-only.yaml, ...
│   └── policies/                  investor-apps-access.yaml
├── pkg/
│   ├── core/
│   │   ├── intent/                AccessPolicy, PolicyEnvelope
│   │   ├── requirement/           RequirementSet, CEL + structured conditions
│   │   ├── adapter/               AdapterCapabilityManifest
│   │   ├── profile/               TargetIntegrationProfile
│   │   ├── mapping/               RequirementMappingSet
│   │   ├── action/                RuntimeActionCatalog
│   │   ├── plan/                  EnforcementPlan
│   │   ├── context/               ContextFact, VendorAssessment, ContextSnapshot, Registry
│   │   ├── risk/                  RiskAssessment, RiskModel, Engine
│   │   └── bundle/                RuntimeBundle, RuntimePolicyPack, RuntimePDPProfile
│   ├── compiler/                  AccessPolicy + profiles → EnforcementPlan
│   └── bundler/                   EnforcementPlan + profile → signed RuntimeBundle
├── registries/
│   ├── context/                   canonical-keys.yaml (25 canonical context keys)
│   └── risk/                      enterprise-access-risk-v1.yaml
└── internal/
    └── signing/                   Ed25519 key generation, signing, verification
```

---

## License

MPL-2.0 — see [LICENSE](LICENSE) and [LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt).
