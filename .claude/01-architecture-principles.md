# 01 Architecture Principles

## Principle 1: Intent stays generic

Kernloom policies must express enterprise intent in generic concepts:

- subject
- resource
- action
- conditions
- effect
- context
- risk
- trust
- assurance
- posture

A Kernloom policy must not directly become a Zscaler, IdP, firewall, eBPF or WAF policy.

Correct:

```yaml
subject.role: investors
resource.application_group: investor-apps
auth.strength: mfa
subject.risk.level: low
device.posture.status: healthy
effect: allow
```

Avoid as source-of-truth:

```yaml
zscaler.user_risk: low
zscaler.device_posture: compliant
zpa.app_segment_group: investor-apps
```

Vendor-native fields may appear in target plans and mappings, but not as the primary enterprise intent.

## Principle 2: PMS manages, PDP decides, PEP enforces

Kernloom Forge/PMS manages intent, models, lifecycle and governance.

PDPs make decisions.

PEPs or vendor sub-control-planes enforce.

```text
Forge / PMS:
  owns intent, models, governance, lifecycle

Compiler:
  translates intent into requirements and plans

PDP:
  decides in a specific decision context

PEP / Adapter / Vendor platform:
  enforces or configures a target
```

## Principle 3: Runtime and config are separate paths

Runtime actions are temporary and fast.

Config changes are durable and reviewable.

```text
Runtime path:
  event → risk/context → runtime PDP → action broker → TTL action

Config path:
  policy/config proposal → PR → compiler → config PDP → review → merge → config adapter
```

Runtime may create proposals for config changes, but runtime must not directly create permanent configuration.

## Principle 4: PIPs are first-class

A Policy Information Point is a source of context or signals.

Examples:

- IdP
- EDR
- MDM
- CMDB
- Zscaler telemetry
- GeoIP
- HR system
- asset inventory
- KLShield telemetry
- Kubernetes inventory

Historically, some signal collection may live inside adapters. In the new design, this should be separated into explicit PIP adapters.

## Principle 5: Adapters expose capabilities; they do not hide semantic loss

Each adapter must publish:

- which canonical requirements it understands
- which it can enforce
- which it can only partially represent
- which require vendor-native delegation
- which are not supported
- which decisions remain inside the vendor platform

Adapters must not silently drop conditions.

## Principle 6: Vendor sub-control-planes are not simple PEPs

Platforms such as Zscaler, Cloudflare, Palo Alto Prisma, Entra Conditional Access, Okta, CrowdStrike or Kubernetes can include:

- their own policy model
- their own PDPs
- their own context model
- their own runtime evaluation
- their own enforcement points

Kernloom must model them as sub-control-planes, not as dumb enforcement points.

## Principle 7: Transparency is a product feature

For every compiled policy, Kernloom must be able to answer:

- What was implemented?
- Where was it implemented?
- What was not implementable?
- What was delegated?
- What was downgraded?
- Who owns runtime context?
- Who owns risk decision?
- Who owns runtime decision?
- Who owns enforcement?
- How portable is this policy?

## Principle 8: Local autonomy is configurable

A local KLIQ may be:

- enforcement-only
- runtime PDP without local risk engine
- runtime PDP with cached global risk
- runtime PDP with local lightweight risk evaluator
- runtime PDP with full local risk engine

This must be a declared capability, not an assumption.

## Principle 9: One generic platform, multiple target types

Kernloom should support these target categories:

- local PEPs, e.g. KLShield, netfilter, Envoy, NGINX
- vendor sub-control-planes, e.g. Zscaler, Cloudflare, Entra, Okta
- identity systems, e.g. IdP, IAM, PAM
- workload platforms, e.g. Kubernetes, service mesh
- network/security devices, e.g. firewall, WAF, gateway
- data/resource systems, e.g. database, SaaS, API gateway

## Principle 10: Compile-time and runtime must both produce evidence

Compile-time evidence:

- enforcement coverage
- requirement mappings
- delegation report
- semantic downgrade report
- validation report

Runtime evidence:

- decision receipts
- enforcement receipts
- signal freshness
- action TTL
- revert status
- drift status

## Principle 11: Git can be the Enterprise PAP

In the MVP, Kernloom may use Git, pull requests and CI as the Enterprise Policy Administration Point.

This means:

- durable policy intent lives in Git
- policy changes happen through pull requests
- versioning is provided by Git commits
- approval is provided by PR review and CODEOWNERS
- validation is provided by CI and Config PDP checks
- Forge consumes approved state from Git

Forge is then not the primary human policy editor. Forge is the compiler, publisher, control-plane orchestrator and transparency engine.

```text
Policy Author
  ↓
PR in Git
  ↓
CI / Config PDP / Reports
  ↓
Review / Approval
  ↓
Merge to main
  ↓
Forge consumes approved state
  ↓
Compiler / Publisher
  ↓
Runtime Packs + Config Plans + Reports
```

A future Forge UI may exist, but it should create pull requests instead of directly changing durable policy truth.
