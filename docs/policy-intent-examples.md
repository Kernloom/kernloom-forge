# Forge Policy Intent Examples For Manual KLIQ Tests

This is the Forge-side copy/paste path for manual KLIQ tests. It shows:

- how to write Natural Intent as the primary human authoring surface;
- how Forge builds a `RuntimePolicyPack` for standalone KLIQ;
- how Forge serves the same intent as a signed `RuntimeBundle` for managed
  mode;
- which variants are useful for simple and more complex policy tests.

The KLIQ-side guide is in `kernloom/_docs/testing/manual-test-guide.md`.

## v0.3.x Quick Path

- Use `forge intent convert --output-dir ... --emit-policy-intent` to create
  canonical policy documents plus a thin digest-pinned `PolicyIntent`.
- Use `forge validate` to check the policy.
- Use `forge intent validate` to check a `PolicyIntent` composition manifest.
- Use `forge compile` or `forge report` to inspect coverage and gaps.
- Use `forge export-runtime-policy` for standalone KLIQ.
- Use `forge build-runtime-bundle` or `forge serve` for managed KLIQ.
- KLIQ never loads natural intent text directly.
- `when ... then alert route ...` can be emitted as DetectionPolicy and
  ResponsePolicy IR, not as an access condition.
- `default deny ...` is recognized by the converter, but still produces a
  warning for now.
- `never ...` is emitted as a guardrail, not as an access condition.

## Mental Model

| Artifact | Created By | Used By | Purpose |
|---|---|---|---|
| Natural Intent `.intent` | Operator / Git-PAP | Forge converter | Human authoring surface |
| `PolicyIntent` | `forge intent convert` / Git-PAP | Forge | Thin manifest that groups canonical policy documents |
| `AccessPolicy` | `forge intent convert` / Git-PAP | Forge | Generated business policy intent |
| `GuardrailPolicy` | `forge intent convert` | Forge, KLIQ runtime resolver | Generated safety invariants such as "never auto-block admins" |
| `DetectionPolicy` | `forge intent convert` | Forge, KLIQ reaction evaluator | Generated stateful detections such as denied-access thresholds |
| `ResponsePolicy` | `forge intent convert` | Forge, KLIQ reaction evaluator | Generated runtime responses such as alert, rate-limit, case creation |
| `AlertRoute` | `forge intent convert` / Git-PAP | Forge, KLIQ alert signal path | Audience, channels, dedupe, acknowledgement and escalation |
| `EnforcementPlan` | `forge compile` | Operator / report | Shows coverage, downgrades, delegation, gaps |
| `RuntimePolicyPack` | `forge export-runtime-policy` | Standalone KLIQ with `--policy-file` | Local RuntimePDP rules |
| `RuntimeBundle` | `forge build-runtime-bundle` or `forge serve` | KLIQ managed mode | Signed bundle with registry snapshot and pack |

Important: `forge compile --output yaml` creates an `EnforcementPlan`, not a
file for `kliq --policy-file`. For standalone KLIQ, always use
`forge export-runtime-policy`.

## PolicyIntent Composition Manifest

`PolicyIntent` is not a runtime policy engine. It is a small manifest that
groups canonical policy documents so Forge can validate the set together.

Example:

```yaml
apiVersion: kernloom.io/v1
kind: PolicyIntent
metadata:
  name: protect-ziti-controller-admin-access-intent
  owner: security
  environment: production
spec:
  protect:
    resource: ziti-controller
    environment: production
  documents:
    access:
      - kind: AccessPolicy
        name: protect-ziti-controller-admin-access
        ref: access.yaml
        digest: sha256:...
    requirements:
      - kind: RequirementPolicy
        name: low-risk-strong-auth
        ref: requirements.yaml
        digest: sha256:...
    guardrails:
      - kind: GuardrailPolicy
        name: protect-ziti-controller-admin-access-guardrails
        ref: guardrails.yaml
        digest: sha256:...
    detections:
      - kind: DetectionPolicy
        name: protect-ziti-controller-admin-access-detections
        ref: detections.yaml
        digest: sha256:...
    responses:
      - kind: ResponsePolicy
        name: protect-ziti-controller-admin-access-responses
        ref: responses.yaml
        digest: sha256:...
    alertRoutes:
      - kind: AlertRoute
        name: alert-route.security-ops
        ref: security-ops-alert-route.yaml
        digest: sha256:...
    capabilityRequirements:
      - kind: CapabilityRequirement
        name: ziti-controller-admin-protection
        ref: capabilities.yaml
        digest: sha256:...
  registries:
    context: &standardRegistry
      name: kernloom-standard
      version: 0.2.0
      digest: sha256:...
    actions: *standardRegistry
    capabilities: *standardRegistry
    granularity: *standardRegistry
    detectionEvaluators: *standardRegistry
    missingContextBehaviors: *standardRegistry
    guardrails: *standardRegistry
    gapHandling: *standardRegistry
    notifications: *standardRegistry
    snapshot: *standardRegistry
  compile:
    target: klshield-local
    mode: runtime-bundle
```

Validate the manifest and the referenced documents:

```bash
./bin/forge intent validate \
  --input examples/policies/protect-ziti-controller-policy-intent.yaml
```

What Forge checks:

- referenced files exist and parse;
- access, requirement, guardrail, detection, response and alert route documents
  are valid;
- response rules reference existing detection IDs;
- alert actions reference existing alert routes;
- runtime response actions are known in the registry and have a TTL when they
  enforce something.

## Natural Intent Authoring Path

Kernloom policy should normally be authored as Natural Intent. This document
shows runnable examples and CLI flows. The vocabulary itself lives in
[`natural-intent-vocabulary-cheat-sheet.md`](natural-intent-vocabulary-cheat-sheet.md).

Use the richer Ziti example when you want to see all generated document kinds:

- `AccessPolicy` for access.
- `RequirementPolicy` for access context requirements.
- `DetectionPolicy` for windowed/signal detections.
- `ResponsePolicy` for alert/rate-limit/block responses.
- `AlertRoute` for notification routing.
- `GuardrailPolicy` for safety invariants.
- `CapabilityRequirement` for required context, features, capabilities and gap
  handling.

The important rule: `PolicyIntent` stays thin. It references those canonical
documents with `sha256:` digests; it is not a mega-YAML replacement for them.

Convert the natural form into canonical documents plus a digest-pinned manifest:

```bash
./bin/forge intent convert \
  --input examples/policies/protect-ziti-controller.intent \
  --output-dir /tmp/kernloom-forge-manual/policies/protect-ziti-controller \
  --emit-policy-intent \
  --owner security \
  --compile-target klshield-local

./bin/forge intent validate \
  --input /tmp/kernloom-forge-manual/policies/protect-ziti-controller/policy-intent.yaml
```

The converter writes warnings for lines that are understood but not emitted into
`AccessPolicy` yet, such as `when ... then ...`, `never ...`, and `default deny`.
`never ...` is written to `guardrails.yaml`. `when ...` is written to
`detections.yaml`, and `then ...` is written to `responses.yaml`. Alert actions
also generate an `AlertRoute` document such as `security-ops-alert-route.yaml`.
`requirements ...` is written to `requirements.yaml`; `capabilities ...` and
`gap_handling ...` are written to `capabilities.yaml`. The `policy-intent.yaml`
manifest references every generated canonical document with a digest.

Current status: Forge accepts either individual generated canonical document
files or a generated `PolicyIntent` for `compile`, `report`,
`export-runtime-policy`, `build-runtime-bundle`, and `serve`.

Example files:

- `examples/policies/protect-ziti-controller.intent`: natural authoring example.
- `examples/policies/manual-edge-access.intent`: small natural authoring example
  for the standalone KLIQ smoke test.
- `examples/policies/admin-apps-zero-trust.intent`: privileged admin app
  access with phishing-resistant MFA, managed device posture and break-glass
  guardrails.
- `examples/policies/finance-payroll-access.intent`: finance/payroll access
  with confidential data context, compliance alerting and approver guardrails.
- `examples/policies/production-database-access.intent`: service-account access
  to a restricted production database with workload attestation and runtime
  pressure controls.
- `examples/policies/ci-cd-production-deploy.intent`: CI/CD automation access
  to the production deployment API.
- `examples/policies/vendor-remote-access.intent`: approved third-party access
  through the zero-trust overlay with scan and deny-burst reactions.
- `examples/policies/public-api-abuse-protection.intent`: internet-facing API
  baseline with signal-driven rate-limit and temporary block responses.
- `examples/policies/multi-pdp-pep.intent`: generic Natural Intent with
  explicit requirements, runtime responses and capability-based auto-placement.
- `examples/policies/investor-apps-access.intent`: block-based natural
  authoring example for investor application access.
- `examples/policies/protect-ziti-controller.yaml`: generated fixture YAML kept
  for parser and loader examples.
- `/tmp/kernloom-forge-manual/policies/protect-ziti-controller/policy-intent.yaml`:
  generated composition manifest when using `--output-dir --emit-policy-intent`.
- `examples/policies/protect-ziti-controller-guardrails.yaml`: generated
  guardrail fixture for the natural `never ...` line.
- `examples/policies/protect-ziti-controller-detections.yaml`: generated
  detection fixture for the natural `when ...` condition.
- `examples/policies/protect-ziti-controller-responses.yaml`: generated
  response fixture for the natural `then ...` action.
- `examples/policies/protect-ziti-controller-capabilities.yaml`: generated
  capability and gap-handling fixture for the natural `capabilities ...` block.
- `examples/policies/security-ops-alert-route.yaml`: reusable/generated-style
  route fixture for alert delivery.

## Setup

```bash
mkdir -p /tmp/kernloom-forge-manual/policies /tmp/kernloom-forge-manual/out

cd /path/to/kernloom-forge
mkdir -p bin
go build -o bin/forge ./cmd/forge
```

Optionally build KLIQ:

```bash
cd /path/to/kernloom
mkdir -p bin
go build -o bin/kliq ./iq/cmd/kliq
```

## 1. Base Intent: Risk And Device Posture

This intent is small enough for the first test, but complete enough to create
two compensating runtime rules. Write it as Natural Intent and let Forge emit
the canonical documents.

```bash
cd /path/to/kernloom-forge

cat > /tmp/kernloom-forge-manual/policies/manual-edge-access.intent <<'EOF'
intent "manual-edge-access"

protect service "public-edge" in "production" as "public edge service"

compose:
  access "manual-edge-access"
  requirements "manual-edge-context"
  detection "manual-edge-runtime-detections"
  response "manual-edge-runtime-responses"
  alert_route "security-ops"
  guardrail "never-autoblock-kernloom-admins"
  capabilities "manual-edge-runtime-capabilities"

access "manual-edge-access":
  allow all

requirements "manual-edge-context":
  require "subject.risk.level" eq "low"
  require "device.posture.status" eq "healthy"

detection "manual-edge-runtime-detections":
  detect "risk-elevated":
    when risk at least medium

  detect "risk-high":
    when risk at least high

  detect "unknown-source-deny":
    when denied access to "public-edge" by unknown source exceeds 5 within 15m

  detect "sustained-pressure":
    when rate_limit drops to "public-edge" by unknown source sustained for 5m

response "manual-edge-runtime-responses":
  on "risk-elevated" then rate_limit source at 100 pps for 15m
  on "risk-high" then alert route "security-ops" severity "high" dedupe 1m
  on "sustained-pressure" then temporary_block source for 10m
    require previous action "enforce.traffic.rate_limit" active
    allow local enforcement state evidence
    require enforcement target excludes group "kernloom-admins"

alert_route "security-ops":
  notify group "kernloom-security-ops"
  via ["log", "email"]
  dedupe by ["tenant.id", "resource.id", "detection.id", "source.identity_or_ip"]
  create case false

guardrail "never-autoblock-kernloom-admins":
  never auto_block group "kernloom-admins"
  never quarantine group "kernloom-admins"
  never disable identity group "kernloom-admins"

capabilities "manual-edge-runtime-capabilities":
  require context "subject.risk.level"
  require context "device.posture.status"
  require windowed_detection
  require traffic_rate_limit
  require temporary_traffic_block

gap_handling:
  fail on missing_context
  require_approval on identity_to_ip downgrade
EOF

./bin/forge intent convert \
  --input /tmp/kernloom-forge-manual/policies/manual-edge-access.intent \
  --output-dir /tmp/kernloom-forge-manual/policies/manual-edge-access \
  --emit-policy-intent \
  --name manual-edge-access \
  --owner lab-operator
```

Registry terms used here:

| Natural phrase | Registry meaning |
|---|---|
| `allow all` | AccessPolicy wildcard subject selector; useful for KLShield-local runtime checks without IdP dependency |
| `access service "public-edge"` | AccessPolicy action/resource selector + Entity Taxonomy |
| `require ... eq ...` | Policy Condition Type Registry + Policy Operator Registry |
| `subject.risk.level` | Context Key + Risk Taxonomy |
| `device.posture.status` | Context Key |
| `when risk equals ...` | Generated `DetectionPolicy` with `metric.threshold` over `subject.risk.level` |
| `when denied access ... by unknown source exceeds ...` | Generated windowed detection over denied access events grouped by unknown source |
| `when rate_limit drops ... sustained ...` | Generated sustained-pressure detection over local rate-limit drop telemetry |
| `rate_limit source at 100 pps for 15m` | Generated TTL-bounded `ResponsePolicy` action `enforce.traffic.rate_limit` with per-decision `rate_pps` |
| `temporary_block source for 10m` | Generated TTL-bounded `ResponsePolicy` action `enforce.traffic.drop` |
| `require previous action ... active` | Response-chaining guard for escalation actions |
| `allow local enforcement state evidence` | KLIQ may use local runtime state as evidence for that chain |
| `require enforcement target excludes group ...` | Blast-radius guard on the response action |
| `capabilities ...` and `gap_handling ...` | Generated `CapabilityRequirement` document referenced by `PolicyIntent` |
| `low`, `healthy`, `unknown` | Allowed canonical values |

## 2. Check The Intent With Forge

```bash
./bin/forge validate \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access/access.yaml

./bin/forge intent validate \
  --input /tmp/kernloom-forge-manual/policies/manual-edge-access/policy-intent.yaml

./bin/forge intent support \
  --input /tmp/kernloom-forge-manual/policies/manual-edge-access.intent \
  --target klshield-local \
  --output /tmp/kernloom-forge-manual/out/manual-edge-support.yaml

./bin/forge compile \
  --intent /tmp/kernloom-forge-manual/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output summary

./bin/forge report \
  --intent /tmp/kernloom-forge-manual/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output /tmp/kernloom-forge-manual/out/manual-edge-report.yaml
```

Expected:

- `manual-edge-access -> klshield-local` appears in the summary.
- `risk_level` and `device_posture` are mapped as `compensating_control` for
  `klshield-local`.
- Context-sensitive compensating controls include `runtimeNotes` that explain
  how missing or unknown evidence is handled.
- `manual-edge-support.yaml` is a `NaturalIntentSupportReport` with
  `enforced`, `carried`, and `warnings` counters for policy writers.
- The generated `PolicyIntent` references a `CapabilityRequirement` document
  for context keys, reaction capabilities and gap handling.
- The report has no unexpected `unsupported` requirements.

Debug:

```bash
grep -E 'target:|deployable:|status:|support:|fidelity:|downgrade|compensating|runtimeNotes|unknown' \
  /tmp/kernloom-forge-manual/out/manual-edge-report.yaml
```

## 3. Build A RuntimePolicyPack For Standalone KLIQ

The normal path is `--intent .../policy-intent.yaml`. The older `--policy`,
`--guardrail`, `--detection`, `--response`, and `--alert-route` flags remain
useful for fixture-level debugging, but they should not be the first manual
workflow.
For source-only adapters, a group guardrail can reject hard actions when the
subject is unknown. That is safer, but it can also prevent source blocks until
identity context is available.

```bash
./bin/forge export-runtime-policy \
  --intent /tmp/kernloom-forge-manual/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --ttl 30s \
  --output /tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml
```

Guarded and routed response variant from the richer Natural Intent example:

```bash
./bin/forge export-runtime-policy \
  --intent /tmp/kernloom-forge-manual/policies/protect-ziti-controller/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --ttl 30s \
  --output /tmp/kernloom-forge-manual/out/protect-ziti-controller-runtime-pack.yaml
```

Check the pack:

```bash
grep -E 'kind: RuntimePolicyPack|capabilities_required:|guardrails:|detection_rules:|response_rules:|alert_routes:|when:|capability:|level:' \
  /tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml
```

Expected:

- `kind: RuntimePolicyPack`
- `guardrails:`, `detection_rules:`, `response_rules:` and `alert_routes:`
  when the generated `PolicyIntent` references those documents
- `capability: enforce.traffic.rate_limit`
- `capability: enforce.traffic.drop`
- a rule for `risk.level in ['medium', 'high', 'critical']`
- a rule for `device.posture.status in ['degraded', 'unhealthy']`
- response rules for `risk-elevated`, `risk-high`, and `sustained-pressure`
- previous-action params such as `previous_action_id`

In the example target `klshield-local`, `risk_level` and `device_posture` are
mapped as compensating restrictions. Forge therefore creates local RuntimePDP
rules for known bad evidence. Missing or unknown context must stay transparent
in the Forge report and must not silently become a hard runtime block.

## 4. Load The Pack In Standalone KLIQ

No-root smoke test without an adapter:

```bash
cd /path/to/kernloom

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file=/tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-forge-manual/out/state-standalone.json \
  --db=/tmp/kernloom-forge-manual/out/kliq-standalone.db \
  --interval=2s
```

Expected:

- `Policy loaded: ... kind=RuntimePolicyPack`
- `[runtime-pdp] pack loaded: 3 rules`
- `RuntimePDP mode: SHADOW`
- no parse or compile errors.

Optional KLShield run, still without real PEP writes:

```bash
sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-forge-manual/out/state-klshield.json \
  --db=/tmp/kernloom-forge-manual/out/kliq-klshield.db \
  --interval=1s
```

Use `--dry-run=false` only after a successful dry-run and a clear operator
decision.

## 5. Managed Mode With A Signed RuntimeBundle

Managed mode tests the signature, registry snapshot, bundle activation, and
RuntimePolicyPack handoff.

Create keys:

```bash
cd /path/to/kernloom-forge

./bin/forge keygen \
  --private /tmp/kernloom-forge-manual/out/forge-runtime.key \
  --public /tmp/kernloom-forge-manual/out/forge-runtime.pub
```

Build one bundle as a file from the generated `PolicyIntent`:

```bash
./bin/forge build-runtime-bundle \
  --intent /tmp/kernloom-forge-manual/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --node-id node-manual-1 \
  --generation 1 \
  --runtime-pdp-mode shadow \
  --failover fail_static \
  --signing-key /tmp/kernloom-forge-manual/out/forge-runtime.key \
  --output /tmp/kernloom-forge-manual/out/manual-edge-runtime-bundle.yaml
```

Check the bundle:

```bash
grep -E 'kind: RuntimeBundle|registry_snapshot:|runtime_policy_pack:|signature:' \
  /tmp/kernloom-forge-manual/out/manual-edge-runtime-bundle.yaml
```

Pre-register the KLIQ node and copy the printed `enroll_token`:

```bash
./bin/forge enroll-token create \
  --store /tmp/kernloom-forge-manual/out/enroll-tokens.yaml \
  --node-id node-manual-1 \
  --ttl 24h
```

Start Forge as the control plane:

```bash
./bin/forge serve \
  --addr :18443 \
  --intent /tmp/kernloom-forge-manual/policies/manual-edge-access/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --signing-key /tmp/kernloom-forge-manual/out/forge-runtime.key \
  --enroll-token-store /tmp/kernloom-forge-manual/out/enroll-tokens.yaml \
  --generation 1 \
  --runtime-pdp-mode shadow \
  --failover fail_static
```

With no `--target`, Forge uses the enrolled node's reported adapter and
effective capabilities to choose the deployable target pack. Add `--target` for
a forced single target, or `--assignments` when you need explicit node
selection by node ID, adapter, capability, or inventory labels.

Health check:

```bash
curl -fsS http://localhost:18443/healthz
```

Start KLIQ in managed mode. Replace `PASTE_ENROLL_TOKEN_HERE` with the token
printed by `forge enroll-token create`:

```bash
cd /path/to/kernloom

timeout 30s ./bin/kliq run \
  --adapter=none \
  --graph-node-id=node-manual-1 \
  --mode=managed \
  --forge-url=http://localhost:18443 \
  --forge-enroll-token=PASTE_ENROLL_TOKEN_HERE \
  --node-labels=role=edge-gateway,env=production,service=public-edge \
  --policy-verify-key=/tmp/kernloom-forge-manual/out/forge-runtime.pub \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-forge-manual/out/state-managed.json \
  --db=/tmp/kernloom-forge-manual/out/kliq-managed.db \
  --interval=2s
```

Expected:

- Forge logs enrollment, heartbeat, and bundle requests.
- KLIQ logs that it applied a RuntimeBundle.
- KLIQ writes `managed/current-bundle.yaml` next to the state file.
- KLIQ rejects bundles without a valid signature or without a registry snapshot.

Note: the Forge API server is still an MVP. Enrollment tokens and session tokens
are stored in memory while the server runs, but the enrollment token store keeps
used/unused token state on disk.

## Variants From Simple To Complex

| Example | Policy | Target | Expected Result |
|---|---|---|---|
| Risk gate only | One condition: `subject.risk.level == low` | `klshield-local` | Small pack with one deny rule for high/critical risk |
| Risk + device posture | Base example above | `klshield-local` | Two compensating runtime rules |
| Investor apps overlay | `examples/policies/investor-apps-access.intent` | `openziti-production` | MFA delegated, risk as compensating runtime control |
| Network tuple governance | Conditions on `network.protocol` and `network.port` | `klshield-local` or `netfilter` | Good report/mapping check; may end without runtime rules |
| Strict admin Config PDP | MFA + risk + device posture, `allowDelegation: false`, `allowSemanticDowngrade: false` | `openziti-production` | Config PDP should deny when delegation or downgrade would be needed |

Investor example:

```bash
cd /path/to/kernloom-forge

./bin/forge intent convert \
  --input examples/policies/investor-apps-access.intent \
  --output-dir /tmp/kernloom-forge-manual/policies/investor-apps \
  --emit-policy-intent \
  --name investor-apps-access \
  --owner security \
  --compile-target openziti-production

./bin/forge report \
  --intent /tmp/kernloom-forge-manual/policies/investor-apps/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output /tmp/kernloom-forge-manual/out/investor-report.yaml

./bin/forge export-runtime-policy \
  --intent /tmp/kernloom-forge-manual/policies/investor-apps/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target openziti-production \
  --ttl 30s \
  --output /tmp/kernloom-forge-manual/out/investor-openziti-pack.yaml
```

Strict Config PDP example:

```bash
./bin/forge config-pdp validate \
  --intent /tmp/kernloom-forge-manual/policies/investor-apps/policy-intent.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target openziti-production \
  --output /tmp/kernloom-forge-manual/out/investor-config-pdp.yaml
```

## Quick Debug

If `export-runtime-policy` creates no rules:

- Check the target profile. Only `compensating_control` creates local runtime
  rules.
- Check the adapter mapping: `examples/adapters/<adapter>/mappings.yaml`.
- Check the runtime action. Grant actions are config/proposal-only.
- For first standalone tests, use `klshield-local` with `risk_level` or
  `device_posture`.

Useful grep commands:

```bash
grep -E 'unsupported|partial|downgrade|compensating|deployable' \
  /tmp/kernloom-forge-manual/out/*.yaml

grep -E 'kind: RuntimePolicyPack|when:|capability:|level:' \
  /tmp/kernloom-forge-manual/out/*pack.yaml

grep -E 'kind: RuntimeBundle|registry_snapshot:|signature:' \
  /tmp/kernloom-forge-manual/out/*bundle.yaml
```
