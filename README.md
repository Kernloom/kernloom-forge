# Kernloom Forge

Forge is the policy governance and compilation plane for the [Kernloom](https://kernloom.com) Zero Trust platform. It translates vendor-neutral enterprise policy intent into enforcement plans, signed runtime bundles, and transparency reports.

Forge does not enforce anything itself. It compiles, signs, and distributes.
KLIQ enforces locally via its PEP adapters (KLShield, netfilter, OpenZiti, …).

---

## Current Release Line

`v0.3.0` focuses on the Forge-to-KLIQ runtime path:

- Write or convert an `AccessPolicy`.
- Compile reports and enforcement plans.
- Export a standalone `RuntimePolicyPack` for `kliq --policy-file`.
- Build or serve a signed `RuntimeBundle` for managed KLIQ.
- Pre-register managed nodes with enrollment tokens.
- Include a pinned registry snapshot from `kernloom-registries`.

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
| `pkg/core/bundle/` | Historical Forge bundle model | legacy |
| `pkg/core/naturalintent/` | Simple natural intent parser/converter to `AccessPolicy` | MVP |
| `pkg/bundler/` | Build KLIQ `kernloom-contracts` RuntimePolicyPack/RuntimeBundle + Sign/Verify (Ed25519) | ✅ |
| `pkg/compiler/` | AccessPolicy → EnforcementPlan | ✅ |
| `pkg/configpdp/` | Validates EnforcementPlan against `enforcementConstraints` | ✅ |
| `pkg/report/` | Coverage, delegation, downgrade and Config PDP reports | ✅ |
| `pkg/conformance/` | KLIQ/Forge runtime contract fixture generator | ✅ |
| `github.com/kernloom/kernloom-registries` | Canonical registry standard consumed by Forge | ✅ |
| Forge Control Plane API | Node enrollment tokens, signed bundle distribution, findings/receipts reception | ✅ MVP |
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

# Export a standalone KLIQ RuntimePolicyPack
./bin/forge export-runtime-policy \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/ \
  --target openziti-production \
  --output /tmp/runtime-policy.yaml

# Build a signed KLIQ RuntimeBundle
./bin/forge keygen --private /tmp/forge-runtime.key --public /tmp/forge-runtime.pub
./bin/forge build-runtime-bundle \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/ \
  --target openziti-production \
  --node-id node-1 \
  --signing-key /tmp/forge-runtime.key \
  --output /tmp/runtime-bundle.yaml

# Pre-register a managed KLIQ node.
# Copy the printed enroll_token into the node config or CLI flag.
./bin/forge enroll-token create \
  --store /tmp/forge-enroll-tokens.yaml \
  --node-id node-1 \
  --ttl 24h

# Serve signed RuntimeBundles to managed KLIQ nodes
./bin/forge serve \
  --addr :8443 \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/ \
  --target openziti-production \
  --signing-key /tmp/forge-runtime.key \
  --enroll-token-store /tmp/forge-enroll-tokens.yaml

# Produce operator reports
./bin/forge report \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/

# Write KLIQ/Forge conformance fixtures
./bin/forge conformance-fixtures --output /tmp/kernloom-conformance
```

Add `--guardrail <GuardrailPolicy.yaml>` to `export-runtime-policy`,
`build-runtime-bundle`, or `serve` when the runtime artifact should include
safety invariants such as "never auto-block admins".

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
      signal: session.authentication.strength
      operator: eq
      value: mfa
      cel: "session.authentication.strength == 'mfa'"
    - id: require-low-risk
      type: risk_level
      signal: subject.risk.level
      operator: eq
      value: low
  effect: allow
```

Conditions support both CEL expressions and structured `signal/operator/value`
format. The policy kind, selectors, condition types, operators and effects are
defined by `github.com/kernloom/kernloom-registries/registries/policy`.

### Natural policy intent

Forge includes a small natural intent converter. It is a convenience layer.
Forge still plans from canonical `AccessPolicy` YAML:

```text
protect "ziti-controller"
allow group "kernloom-admins" to access "ziti-controller"
require "subject.risk.level" eq "low"
require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]
default deny access to "ziti-controller"
when denied access to "ziti-controller" exceeds 5 within 15m then alert
never auto_block group "kernloom-admins"
```

Quotes are optional around simple variable values and useful to show which
tokens are data rather than language.

`alert` is a natural alias for the canonical observe action
`observe.signal.emit`. Other standard response actions include
`rate_limit`, `deny`, `network_deny`, `drop`, `tarpit`, and `quarantine`, or
their canonical IDs from the registry.

Convert that text to YAML:

```bash
./bin/forge intent convert \
  --input examples/policies/protect-ziti-controller.intent \
  --output /tmp/protect-ziti-controller.yaml \
  --guardrails-output /tmp/protect-ziti-controller-guardrails.yaml \
  --owner security
```

Current limits:

- `protect`, `allow` and `require` are emitted into `AccessPolicy`.
- `never ...` can be emitted into a separate `GuardrailPolicy` with
  `--guardrails-output`.
- `default deny` and `when ... then ...` are recognized and reported as
  warnings for now.
- Response rules still need a dedicated compiler IR.

The generated YAML can then move through:

1. an `AccessPolicy` YAML document for the access intent;
2. an optional `GuardrailPolicy` YAML document for safety invariants;
3. an `EnforcementPlan` for operator review;
4. a `RuntimePolicyPack` for standalone KLIQ via `export-runtime-policy`;
5. a signed `RuntimeBundle` for managed KLIQ via `build-runtime-bundle` or
   `serve`.

The importer is a thin parser/converter, not a second policy model. Lines such
as `when ... then ...` are accepted as intent text but currently reported as
warnings until response-policy schemas are added.

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
# In exported KLIQ RuntimePolicyPack:
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
spec:
  capabilities_required:
    - enforce.access.deny
  rules:
    - id: compensating-require-low-risk-openziti-production
      when: "risk.level in ['high', 'critical']"
      then:
        capability: enforce.access.deny
        level: block
        ttl: 30s
```

`forge build-runtime-bundle` wraps that policy pack in a signed
`kind: RuntimeBundle` from `github.com/kernloom/kernloom-contracts`. `forge
serve` can now generate the same signed bundle dynamically for
`GET /api/v1/nodes/{id}/runtime-bundle` when started with `--policy`,
`--adapters`, `--profiles`, `--target` and `--signing-key`.

### Context and Risk

Canonical context, risk, capability, action, signal, metric, scope and
granularity semantics live in `github.com/kernloom/kernloom-registries`.
Forge consumes that module, pins a registry digest into RuntimeBundles and
uses the snapshot as the source of truth for KLIQ managed-mode validation.

The risk engine is a pure function: `Evaluate(model, snapshot, indicators) → EvalResult`. Used for Forge simulation/validation, KLIQ local evaluation, and Correlate global aggregation.

---

## Repository layout

```
kernloom-forge/
├── cmd/forge/                     CLI entry point (compile, export-runtime-policy, bundle, report, serve)
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
│   │   └── bundle/                Historical Forge-local bundle structs
│   ├── compiler/                  AccessPolicy + profiles → EnforcementPlan
│   ├── configpdp/                 enforcementConstraints validation
│   ├── report/                    coverage/delegation/downgrade report set
│   ├── conformance/               KLIQ/Forge fixture generator
│   └── bundler/                   EnforcementPlan + profile → KLIQ contracts RuntimeBundle
└── internal/
    └── signing/                   Ed25519 key generation, signing, verification
```

---

## License

MPL-2.0 — see [LICENSE](LICENSE) and [LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt).
