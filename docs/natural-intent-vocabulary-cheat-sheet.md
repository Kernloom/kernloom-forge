# Natural Intent Vocabulary Cheat Sheet

This is the quick authoring vocabulary for Kernloom Natural Intent. It uses the
human-friendly words accepted by Forge and shows the canonical registry meaning
they compile to.

For the registry standard behind these words, see
`kernloom-registries/docs/registry-reference-for-policy-intents.md`.

## Minimal Shape

```text
intent "protect-admin-apps"

protect application_group "admin-apps" in "production"

compose:
  access "admin-apps-access"
  requirements "admin-apps-context"
  detection "admin-apps-detections"
  response "admin-apps-responses"
  alert_route "security-ops"
  guardrail "never-autoblock-admins"
  capabilities "admin-apps-capabilities"

access "admin-apps-access":
  default deny access to "admin-apps"
  allow group "platform-admins" to access application_group "admin-apps"

requirements "admin-apps-context":
  require "subject.risk.level" eq "low"
  require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]
  require "device.posture.status" eq "healthy"
```

`Natural Intent` is the authoring surface. Forge converts it into canonical
documents: `AccessPolicy`, `RequirementPolicy`, `DetectionPolicy`,
`ResponsePolicy`, `AlertRoute`, `GuardrailPolicy`, `CapabilityRequirement` and a
thin digest-pinned `PolicyIntent`.

## Blocks

| Block | Use For |
|---|---|
| `intent "name"` | Optional policy base name. |
| `protect <resource> in <environment>` | Main protected resource and environment. |
| `compose:` | Optional explicit list of generated document members. |
| `access "name":` | Who may access what. |
| `requirements "name":` | Context requirements that must be true for access. |
| `detection "name":` | Stateful or signal-based detections. |
| `response "name":` | Runtime reactions after detections fire. |
| `alert_route "name":` | Alert audience, channels, dedupe, acknowledgement. |
| `guardrail "name":` | Safety invariants such as never auto-block admins. |
| `capabilities "name":` | Required target capabilities and context. |
| `gap_handling:` | What Forge should do when target support is incomplete. |

## Subjects And Resources

| Natural Subject | Meaning |
|---|---|
| `all`, `everyone`, `any` | Wildcard subject. |
| `group "platform-admins"` | Group selector. |
| `role "sre"` | Role selector. |
| `user "alice"` | User identity. |
| `service_account "deploy-bot"` | Service account. |
| `workload "payments-api"` | Workload identity. |
| `device_identity "laptop-123"` | Device identity. |
| `automation_identity "ci-runner"` | Automation identity. |
| `external_partner "vendor-a"` | External partner identity. |

| Natural Resource | Meaning |
|---|---|
| `application "crm"` | Single application. |
| `application_group "admin-apps"` | Application group. |
| `api "public-api"` | API resource. |
| `service "ziti-controller"` | Service resource. |
| `endpoint "edge-node"` | Endpoint. |
| `database "customer-prod-db"` | Database. |
| `storage "s3-prod"` | Storage. |
| `secret "vault-prod"` | Secret. |
| `network_segment "prod-vpc"` | Network segment. |
| `infrastructure_asset "bastion-1"` | Infrastructure asset. |

If no type is given, Forge uses the default subject/resource type for the
converter call.

## Access Lines

| Natural Line | Canonical Meaning |
|---|---|
| `allow group "admins" to access "ziti-controller"` | AccessPolicy allow rule. |
| `allow all` | Wildcard subject access. |
| `default deny access to "ziti-controller"` | Recognized as target/runtime default behavior. |
| `protect "ziti-controller" in "production" as "critical admin interface"` | Resource, environment and description hint. |

## Requirement Vocabulary

Use `require` for access conditions. These compile to `RequirementPolicy`
conditions and remain part of the canonical policy truth.

| Natural Phrase | Canonical Context Key |
|---|---|
| `risk`, `subject risk`, `subject risk level` | `subject.risk.level` |
| `session authentication`, `session authentication strength` | `session.authentication.strength` |
| `posture`, `device posture`, `device posture status` | `device.posture.status` |
| `device managed`, `device management status` | `device.management.status` |
| `edr`, `device edr status` | `device.edr.status` |
| `device attestation status` | `device.attestation.status` |
| `resource criticality`, `criticality` | `resource.criticality` |
| `resource environment`, `environment` | `resource.environment` |
| `resource exposure`, `exposure` | `resource.exposure` |
| `data class`, `resource data class` | `resource.data_class` |
| `session network zone` | `session.network_zone` |
| `network source`, `network destination` | `network.source`, `network.destination` |
| `network protocol`, `network port`, `network zone` | `network.protocol`, `network.port`, `network.zone` |

You can also write canonical keys directly:

```text
require "subject.risk.level" eq "low"
require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]
require "device.posture.status" eq "healthy"
require "resource.environment" eq "production"
```

## Operators And Values

| Operator | Meaning |
|---|---|
| `eq`, `equals`, `is` | Equal. |
| `neq`, `not` | Not equal. |
| `gt`, `gte`, `lt`, `lte` | Numeric/order comparison where the key supports it. |
| `in` | Value is in list. |
| `not_in` | Value is not in list. Missing context is still unknown, not true. |

Common canonical values:

| Key | Values |
|---|---|
| Risk | `low`, `medium`, `high`, `critical`, `unknown` |
| Auth strength | `none`, `password`, `mfa`, `phishing_resistant_mfa` |
| Device posture | `healthy`, `degraded`, `unhealthy`, `unknown` |
| Device management | `managed`, `unmanaged`, `unknown` |
| Resource environment | `development`, `staging`, `production`, `dr` |
| Resource criticality | `low`, `medium`, `high`, `critical` |
| Resource exposure | `internal`, `partner`, `internet`, `unknown` |
| Network protocol | `tcp`, `udp`, `icmp`, `other`, `unknown` |
| Network zone | `internal`, `dmz`, `external`, `vpn`, `zero_trust_overlay`, `unknown` |

`unknown` is a real state. It must not be treated as `low` or `healthy`.

## Detection Vocabulary

Use `detection` blocks when something must be observed over time.

```text
detection "edge-detections":
  detect "unknown-source-deny":
    when denied access to "public-edge" by unknown source exceeds 5 within 15m

  detect "sustained-pressure":
    when rate_limit drops to "public-edge" by unknown source sustained for 5m

  detect "risk-medium":
    when risk equals medium

  detect "high-score-signal":
    when signal "source.scan_suspected" score gte 80
```

| Natural Detection | Meaning |
|---|---|
| `when denied access to <resource> exceeds <n> within <duration>` | Windowed denied-access detection. |
| `by unknown source` | Match unknown source selector. |
| `by known subject` | Match known subject selector. |
| `by known subject excluding group "admins"` | Match known subject, excluding a protected group. |
| `by group "admins"` | Match a group selector. |
| `when rate_limit drops to <resource> ... sustained for <duration>` | Sustained local rate-limit pressure. |
| `when risk equals medium` | Metric/context threshold over `subject.risk.level`. |
| `when risk at least high` | Ordered risk threshold; expands to `high` or `critical`. |
| `when signal "<signal-id>" score gte 80` | Signal threshold detection. |

Durations use Go-style duration strings such as `30s`, `5m`, `15m`, `1h`.

## Response Vocabulary

Use `response` blocks for bounded runtime reactions after detections fire.

```text
response "edge-responses":
  on "risk-medium" then alert route "security-ops" severity "high" dedupe 15m
  on "risk-medium" then rate_limit source at 100 pps for 15m
  on "sustained-pressure" then temporary_block source for 10m
    require previous action "enforce.traffic.rate_limit" active
    require risk confidence at least high
    require risk signal fresher than 2m
    require at least 2 independent signals before block
    allow local enforcement state evidence
    require enforcement target excludes group "platform-admins"
```

| Natural Action | Canonical Action |
|---|---|
| `alert route "security-ops" severity "medium" dedupe 15m` | `notify.alert.emit` |
| `finding` | `export.finding` |
| `rate_limit` | `enforce.traffic.rate_limit` |
| `connection_limit` | `enforce.traffic.connection_limit` |
| `bandwidth_limit` | `enforce.traffic.bandwidth_limit` |
| `syn_protect` | `enforce.network.syn_protect` |
| `deny`, `block` | `enforce.access.deny` |
| `temporary_block`, `drop` | `enforce.traffic.drop` |
| `network_deny` | `enforce.network.deny` |
| `tarpit` | `enforce.traffic.tarpit` |
| `quarantine` | `enforce.network.quarantine` |

Response targets:

| Target | Meaning |
|---|---|
| `source` | Apply to source identity/IP. |
| `subject` | Apply to subject. |
| `resource` | Apply to resource. |

Response requirements:

| Natural Requirement | Meaning |
|---|---|
| `require previous action "enforce.traffic.rate_limit" active` | Stronger action may run only after that action is still active. |
| `require risk confidence at least high` | Harder action requires high-confidence local risk. |
| `require risk signal fresher than 2m` | Harder action requires a recent risk assessment. |
| `require at least 2 independent signals before block` | Harder action requires distinct signal evidence, exposed to RuntimePDP as `risk.independent_signal_count`. |
| `allow local enforcement state evidence` | KLIQ may use local runtime state as evidence for the previous action. |
| `require enforcement target excludes group "platform-admins"` | Blast-radius guard; protected group must not be hit by a hard action. |

Do not call this `FSM` in policy text. `FSM` is an internal implementation
detail. The policy vocabulary is `previous action` and `local enforcement state
evidence`.

## Alert Route Vocabulary

```text
alert_route "security-ops":
  notify group "kernloom-security-ops"
  via ["log", "email"]
  dedupe by ["tenant.id", "resource.id", "detection.id", "source.identity_or_ip"]
  create case false
  require acknowledgement within 30m
  escalate if unacknowledged to group "incident-commanders"
```

| Natural Line | Meaning |
|---|---|
| `notify group "security-ops"` | Audience for the route. |
| `via ["log", "email"]` | Notification channels. |
| `dedupe by [...]` | Deduplication keys. |
| `create case true/false` | Whether this route creates an incident/case. |
| `require acknowledgement within 30m` | Ack timeout. |
| `escalate if unacknowledged to group "..."` | Escalation audience. |

Channel refs are registry-bound in generated policy, for example
`log.*`, `stdout`, `stderr`, `channel.*`, `mailinglist.*` or `email.*`.
KLIQ's first local notification dispatcher supports `log` and SMTP-backed
`email`; other channel types are validated and carried for upstream systems.

## Guardrail Vocabulary

```text
guardrail "never-autoblock-admins":
  never auto_block group "platform-admins"
  never quarantine group "platform-admins"
  never disable identity group "platform-admins"
```

| Natural Guardrail | Forbids |
|---|---|
| `never auto_block group "admins"` | Traffic drop, access deny, quarantine and identity disable for that group. |
| `never quarantine group "admins"` | Network quarantine for that group. |
| `never disable identity group "admins"` | Identity disable for that group. |
| `never deny group "admins"` | Access deny for that group. |

## Capabilities And Gaps

```text
capabilities "edge-runtime-capabilities":
  require identity_based_access
  require context "subject.risk.level"
  require context "device.posture.status"
  require windowed_detection
  require traffic_rate_limit
  require temporary_traffic_block

gap_handling:
  fail on missing_context
  require_approval on identity_to_ip downgrade
```

| Natural Capability | Meaning |
|---|---|
| `require context "subject.risk.level"` | Target/PIP must provide this context. |
| `require identity_based_access` | Target must preserve identity semantics. |
| `require windowed_detection` | Target/runtime must support stateful detection. |
| `require traffic_rate_limit` | Needs `enforce.traffic.rate_limit`. |
| `require temporary_traffic_block` | Needs `enforce.traffic.drop`. |

Common gap IDs:

| Gap | Typical Behavior |
|---|---|
| `missing_context` | `fail`, `require_approval`, `degrade_to_alert` |
| `identity_to_ip downgrade` | `require_approval` or `fail` |
| `semantic_downgrade` | `require_approval` |
| `enforcement_gap` | `fail` |
| `granularity_gap` | `require_approval` |

## Rules Of Thumb

- Write business access requirements with `require`, not `when`.
- Write reactions with `detection` plus `response`, not as access conditions.
- Prefer `rate_limit` before `temporary_block`; gate stronger responses with
  `require previous action ... active`.
- Keep `PolicyIntent` thin: it should reference canonical documents with
  versions and digests.
- Unknown or missing context is not success. Treat it as `unknown`, report it,
  deny or require review according to policy.
- Use canonical IDs directly when precision matters.
