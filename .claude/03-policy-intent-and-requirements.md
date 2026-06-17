# 03 Policy Intent and Requirements

## Goal

Kernloom policies express security intent without binding that intent to a specific product.

A policy should describe:

- who
- may do what
- to which resource
- under which conditions
- with which effect

## Generic Access Policy shape

```yaml
apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: investor-apps-access
  owner: security-architecture
  environment: prod
spec:
  subject:
    type: role
    ref: investors
  action: access
  resource:
    type: application_group
    ref: investor-apps
  conditions:
    - id: require-mfa
      type: authentication_strength
      signal: subject.auth_strength
      operator: gte
      value: mfa
    - id: require-low-risk
      type: risk_level
      signal: subject.risk.level
      operator: eq
      value: low
    - id: require-healthy-device
      type: device_posture
      signal: device.posture.status
      operator: eq
      value: healthy
  effect: allow
```

## Canonical objects

Minimum useful object model:

```text
Subject:
  subject.user
  subject.group
  subject.role
  subject.service_account
  subject.workload

Resource:
  resource.application
  resource.application_group
  resource.api
  resource.service
  resource.database
  resource.network_segment
  resource.data_class

Action:
  access
  connect
  read
  write
  administer
  publish
  execute

Authentication:
  subject.auth_strength
  session.auth_method
  session.assurance_level

Risk:
  subject.risk.level
  device.risk.level
  session.risk.level
  resource.risk.level

Device:
  device.posture.status
  device.trust.level
  device.managed
  device.edr.status

Session:
  session.location
  session.network
  session.time
  session.ip
  session.auth_strength

Effect:
  allow
  deny
  require_step_up
  restrict
  monitor
  isolate
  rate_limit
```

## Requirement extraction

The compiler extracts canonical requirements from a policy.

Input:

```text
investors may access investor-apps only with MFA, low risk and healthy device
```

Output:

```yaml
apiVersion: kernloom.io/v1
kind: RequirementSet
metadata:
  sourcePolicy: investor-apps-access
requirements:
  - id: req-001
    type: subject_match
    object: subject.role
    operator: eq
    value: investors
  - id: req-002
    type: resource_match
    object: resource.application_group
    operator: eq
    value: investor-apps
  - id: req-003
    type: authentication_strength
    object: subject.auth_strength
    operator: gte
    value: mfa
  - id: req-004
    type: risk_level
    object: subject.risk.level
    operator: eq
    value: low
  - id: req-005
    type: device_posture
    object: device.posture.status
    operator: eq
    value: healthy
  - id: req-006
    type: effect
    value: allow
```

## Canonical Requirement Registry

```yaml
apiVersion: kernloom.io/v1
kind: CanonicalRequirementRegistry
requirements:
  - type: subject_match
    objects:
      - subject.user
      - subject.group
      - subject.role
      - subject.workload
  - type: resource_match
    objects:
      - resource.application
      - resource.application_group
      - resource.api
      - resource.service
      - resource.database
  - type: authentication_strength
    objects:
      - subject.auth_strength
      - session.auth_strength
    values:
      - password
      - mfa
      - phishing_resistant_mfa
  - type: risk_level
    objects:
      - subject.risk.level
      - session.risk.level
      - device.risk.level
    values:
      - low
      - medium
      - high
      - critical
  - type: device_posture
    objects:
      - device.posture.status
    values:
      - healthy
      - degraded
      - unhealthy
      - unknown
  - type: effect
    values:
      - allow
      - deny
      - require_step_up
      - restrict
      - monitor
      - isolate
```

## Important rule

A target adapter must never silently drop a requirement.

If a target cannot enforce `subject.risk.level == low`, the compiler must produce:

```text
Status: not enforceable
Reason: no risk signal or evaluation capability available in this target
```

or:

```text
Status: delegated
Reason: target uses vendor-native risk semantics
```

## Policy variants to support later

Initial MVP:

- AccessPolicy
- RuntimeActionPolicy
- ConfigGuardPolicy

Later:

- RiskModelPolicy
- ContextMappingPolicy
- DataProtectionPolicy
- MicrosegmentationPolicy
- WorkloadIdentityPolicy
- NetworkExposurePolicy
- DetectionPolicy
- ResponsePolicy
