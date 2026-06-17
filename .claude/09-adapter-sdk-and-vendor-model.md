# 09 Adapter SDK and Vendor Model

## Goal

Kernloom should allow vendors and third parties to publish adapters for their own platforms.

Adapters must be explicit about:

- target type
- supported modes
- capabilities
- requirement mappings
- target plan schema
- ownership/delegation behavior
- runtime action constraints
- telemetry/PIP outputs

## Adapter package structure

```text
adapter-package/
├── adapter.yaml
├── capabilities.yaml
├── requirement-mapping.yaml
├── context-mapping.yaml
├── target-plan.schema.yaml
├── reports.schema.yaml
├── runtime-actions.yaml
├── examples/
│   ├── access-policy-example.yaml
│   └── deployment-plan-example.yaml
└── implementation/
    ├── client
    ├── config-writer
    ├── telemetry-reader
    └── runtime-action-executor
```

## Adapter manifest

```yaml
apiVersion: kernloom.io/v1
kind: AdapterManifest
metadata:
  name: zscaler
  vendor: zscaler
  version: 0.1.0
spec:
  targetType: vendor_sub_control_plane
  modes:
    - config_write
    - pip_read
    - telemetry_read
    - runtime_delegated
  sourceOfTruth:
    durableConfig: git
  ownership:
    supportsRuntimeDelegation: true
    supportsEnterpriseOwnedRuntimeDecision: limited
  safety:
    requiresApprovalForConfigWrite: true
    supportsDryRun: true
    supportsDriftDetection: true
```

## Capability manifest

```yaml
apiVersion: kernloom.io/v1
kind: AdapterCapabilityManifest
metadata:
  adapter: zscaler
capabilities:
  - id: subject.group
    requirementType: subject_match
    canonicalObject: subject.group
    targetObject: zscaler.scim_group
    support: full
  - id: resource.application_group
    requirementType: resource_match
    canonicalObject: resource.application_group
    targetObject: zscaler.application_segment_group
    support: full
  - id: risk.user
    requirementType: risk_level
    canonicalObject: subject.risk.level
    targetObject: zscaler.user_risk
    support: full_vendor_native
    delegation:
      runtimeContextOwner: zscaler
      riskDecisionOwner: zscaler
      runtimeDecisionOwner: zscaler
  - id: posture.device
    requirementType: device_posture
    canonicalObject: device.posture.status
    targetObject: zscaler.device_posture
    support: full_vendor_native
    delegation:
      runtimeContextOwner: zscaler
      runtimeDecisionOwner: zscaler
```

## Requirement mapping

```yaml
apiVersion: kernloom.io/v1
kind: RequirementMapping
metadata:
  adapter: zscaler
mappings:
  - from:
      requirementType: subject_match
      object: subject.group
    to:
      object: zscaler.scim_group
      field: name
    fidelity: high
  - from:
      requirementType: resource_match
      object: resource.application_group
    to:
      object: zscaler.application_segment_group
      field: name
    fidelity: high
  - from:
      requirementType: risk_level
      object: subject.risk.level
    to:
      object: zscaler.user_risk
      field: risk_level
    fidelity: medium
    delegation:
      status: runtime_delegated
```

## Context mapping

PIP adapters must declare context they provide.

```yaml
apiVersion: kernloom.io/v1
kind: ContextMapping
metadata:
  adapter: zscaler-pip
mappings:
  - from:
      object: zscaler.user_risk
      field: risk_level
    to:
      object: subject.risk.external_assessment.zscaler
    freshness:
      maxAge: 15m
    confidence: vendor_native
  - from:
      object: zscaler.device_posture
      field: posture_status
    to:
      object: device.posture.external_assessment.zscaler
    confidence: vendor_native
```

## Runtime actions

Runtime action adapters must declare hard constraints.

```yaml
apiVersion: kernloom.io/v1
kind: RuntimeActionManifest
metadata:
  adapter: zscaler-runtime-action
supportedActions:
  - action: restrict_user
    maxTtl: 1h
    requiresAudit: true
    requiresAutoRevert: true
    allowedScopes:
      - user
      - group
    forbiddenTargets:
      - permanent_access_policy
```

## Config adapter contract

A config adapter receives a validated target deployment plan.

It must not interpret generic policy intent itself.

Input:

```text
TargetDeploymentPlan
ConfigPDPValidationReport
Approved Git commit
```

Output:

```text
DeploymentReceipt
DriftStatus
Errors
```

## Runtime action adapter contract

A runtime action adapter receives a runtime decision with constraints.

Input:

```text
RuntimeDecision
ActionConstraints
TTL
Scope
AuditMetadata
```

Output:

```text
EnforcementReceipt
AutoRevertReceipt
```

## PIP adapter contract

A PIP adapter emits context values or signals.

Output:

```text
ContextValue
Signal
VendorAssessment
TelemetryEvent
```

## Vendor publication model

Vendors should be able to publish adapter packages that Kernloom can verify.

Validation should check:

- schema correctness
- declared capabilities
- mapping consistency
- forbidden silent drops
- delegation declarations
- safety constraints
- version compatibility

## Trust model

Vendor adapters must not be trusted blindly.

Kernloom should support:

- signed adapter manifests
- allowlisted adapter versions
- conformance tests
- dry-run mode
- sandbox execution for mapping logic
- policy validation before deployment

## Role-separated adapter packages

Vendors may publish one integration package, but the package must expose roles separately.

Example:

```text
zscaler-adapter-package/
├── manifest.yaml
├── capabilities.yaml
├── requirement-mapping.yaml
├── context-mapping.yaml
├── read-adapter/
│   └── provides PIP / actual state / telemetry
├── config-adapter/
│   └── writes durable config if enabled
├── runtime-action-adapter/
│   └── executes temporary actions if supported
└── schemas/
    └── target deployment plan schemas
```

A deployment may enable only a subset:

```yaml
enabledRoles:
  - pip_read
  - config_validation_target
  - runtime_delegated

disabledRoles:
  - config_write
  - runtime_action
```

This supports a Zscaler MVP where Kernloom validates config and reads actual state, while platform-owned pipelines deploy config and Zscaler owns runtime.
