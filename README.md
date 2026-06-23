# Kernloom Forge

Forge is the policy governance and compilation plane for the [Kernloom](https://kernloom.com) Zero Trust platform. It translates vendor-neutral enterprise policy intent into enforcement plans, signed runtime bundles, and transparency reports.

Forge does not enforce anything itself. It compiles, signs, and distributes.
KLIQ enforces locally via its PEP adapters (KLShield, netfilter, OpenZiti, …).

---

## Current Release Line

`v0.3.x` focuses on the Forge-to-KLIQ runtime path:

- Write Natural Intent and convert it to canonical policy documents plus a
  thin `PolicyIntent`.
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
| `pkg/core/response/` | DetectionPolicy, ResponsePolicy, AlertRoute runtime IR | MVP |
| `pkg/core/bundle/` | Historical Forge bundle model | legacy |
| `pkg/core/naturalintent/` | Natural Intent parser/converter to canonical policy documents | MVP |
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

# Convert human-authored intent into canonical docs + PolicyIntent
./bin/forge intent convert \
  --input examples/policies/investor-apps-access.intent \
  --output-dir /tmp/kernloom-forge/investor-apps \
  --emit-policy-intent \
  --owner security

# Compile the generated PolicyIntent against adapter profiles
./bin/forge compile \
  --intent /tmp/kernloom-forge/investor-apps/policy-intent.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/

# Validate generated canonical documents and refs
./bin/forge intent validate \
  --input /tmp/kernloom-forge/investor-apps/policy-intent.yaml

# Explain Natural Intent support status before export/deployment
./bin/forge intent support \
  --input examples/policies/investor-apps-access.intent \
  --target openziti-production \
  --output /tmp/kernloom-forge/investor-apps-support.yaml

# Validate an adapter capability manifest
./bin/forge validate-adapter --adapter examples/adapters/openziti/capability.yaml

# Export a standalone KLIQ RuntimePolicyPack
./bin/forge export-runtime-policy \
  --intent /tmp/kernloom-forge/investor-apps/policy-intent.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/ \
  --target openziti-production \
  --output /tmp/runtime-policy.yaml

# Build a signed KLIQ RuntimeBundle
./bin/forge keygen --private /tmp/forge-runtime.key --public /tmp/forge-runtime.pub
./bin/forge build-runtime-bundle \
  --intent /tmp/kernloom-forge/investor-apps/policy-intent.yaml \
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
  --intent /tmp/kernloom-forge/investor-apps/policy-intent.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/ \
  --signing-key /tmp/forge-runtime.key \
  --enroll-token-store /tmp/forge-enroll-tokens.yaml

# Produce operator reports
./bin/forge report \
  --intent /tmp/kernloom-forge/investor-apps/policy-intent.yaml \
  --adapters examples/adapters/ \
  --profiles examples/profiles/

# Write KLIQ/Forge conformance fixtures
./bin/forge conformance-fixtures --output /tmp/kernloom-conformance
```

The generated `PolicyIntent` is the normal Forge input. Low-level flags such as
`--policy`, `--guardrail`, `--detection`, `--response`, and `--alert-route`
remain available for fixture debugging and generated artifact inspection.

---

## Key concepts

### Natural Intent — human authoring surface

Operators should normally author policy in `.intent` files:

```text
intent "investor-apps-access"

protect application_group "investor-apps" in "production"

compose:
  access "investor-apps-access"
  requirements "investor-apps-context"
  detection "investor-apps-runtime-detections"
  response "investor-apps-runtime-responses"
  alert_route "security-ops"

access "investor-apps-access":
  default deny access to application_group "investor-apps"
  allow role "investors" to access application_group "investor-apps"

requirements "investor-apps-context":
  require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]
  require "subject.risk.level" eq "low"
```

Forge converts that text into canonical policy documents. Those generated
documents are the stable machine contract; humans should not have to hand-write
the YAML in normal workflows.

### Generated PolicyIntent And Canonical Documents

Natural Intent may also describe detections, routed alerts and guardrails:

```text
intent "protect-ziti-controller-admin-access"

protect "ziti-controller" in "production"

access "ziti-controller-admin-access":
  default deny access to "ziti-controller"
  allow group "kernloom-admins" to access "ziti-controller"

requirements "low-risk-strong-auth":
  require "subject.risk.level" eq "low"
  require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]

detection "ziti-controller-denied-access":
  detect "unknown-source-heavy-deny":
    when denied access to "ziti-controller" by unknown source exceeds 20 within 15m

response "ziti-controller-deny-escalation":
  on "unknown-source-heavy-deny" then rate_limit source for 15m

guardrail "never-autoblock-kernloom-admins":
  never auto_block group "kernloom-admins"

capabilities "ziti-controller-admin-protection":
  require context "subject.risk.level"
  require windowed_detection
  require traffic_rate_limit

gap_handling:
  fail on missing_context
```

Quotes are optional around simple variable values and useful to show which
tokens are data rather than language.

`alert` is a routed notification action. It must name an `AlertRoute`, a
severity, and a dedupe window. Technical response actions include `rate_limit`,
`deny`, `network_deny`, `drop`, `tarpit`, `temporary_block`, and `quarantine`,
or their canonical IDs from the registry. `capabilities` and `gap_handling`
emit a referenced `CapabilityRequirement` document.

For managed KLIQ, `forge serve` can omit `--target`. Forge then uses the
enrolled node's reported adapter and capabilities to choose the deployable
target pack. Use `--target` for a forced single target, or `--assignments` when
you need explicit node selection. Assignment selectors can match node IDs,
adapters, capabilities, and inventory labels such as `role=edge-gateway`,
`env=production`, or `service=payment-api`.

Convert that text to canonical documents plus a digest-pinned manifest:

```bash
./bin/forge intent convert \
  --input examples/policies/protect-ziti-controller.intent \
  --output-dir /tmp/kernloom-forge/protect-ziti-controller \
  --emit-policy-intent \
  --owner security \
  --compile-target klshield-local
```

That output directory contains `policy-intent.yaml` plus generated canonical
documents such as `access.yaml`, `detections.yaml`, `responses.yaml`,
`guardrails.yaml`, `capabilities.yaml`, and `security-ops-alert-route.yaml`. `default deny` is
recognized and reported as a warning for now; it will become its own target
default/runtime-default IR instead of being hidden in `AccessPolicy`.

The generated `PolicyIntent` then moves through:

1. `forge intent validate` for digest, kind and cross-reference checks;
2. `forge compile` / `forge report` for operator review;
3. `forge export-runtime-policy` for standalone KLIQ via `--policy-file`;
4. `forge build-runtime-bundle` or `forge serve` for managed KLIQ.

The importer is a thin parser/converter, not a second policy model.

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
│   └── policies/                  *.intent authoring examples + generated YAML fixtures
├── pkg/
│   ├── core/
│   │   ├── intent/                AccessPolicy, PolicyIntent, PolicyEnvelope
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
