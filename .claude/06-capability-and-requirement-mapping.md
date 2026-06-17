# 06 Capability and Requirement Mapping

## Goal

Kernloom must know what each target can actually implement.

This requires two layers:

1. Capability Mapping
2. Requirement Mapping

## Capability Mapping

Capability Mapping answers:

> Can this target understand or enforce this kind of requirement?

Example:

```yaml
apiVersion: kernloom.io/v1
kind: AdapterCapabilityManifest
metadata:
  adapter: zscaler
capabilities:
  - id: zscaler.subject.group
    requirementType: subject_match
    canonicalObject: subject.role
    targetObject: zscaler.scim_group
    support: full
  - id: zscaler.resource.app_group
    requirementType: resource_match
    canonicalObject: resource.application_group
    targetObject: zscaler.application_segment_group
    support: full
  - id: zscaler.risk.user
    requirementType: risk_level
    canonicalObject: subject.risk.level
    targetObject: zscaler.user_risk
    support: full_vendor_native
    delegation:
      runtimeContextOwner: zscaler
      riskDecisionOwner: zscaler
      runtimeDecisionOwner: zscaler
```

## Requirement Mapping

Requirement Mapping answers:

> How exactly is this canonical requirement represented in this target?

Example:

```yaml
apiVersion: kernloom.io/v1
kind: RequirementMapping
metadata:
  adapter: zscaler
mappings:
  - from:
      requirementType: subject_match
      object: subject.role
    to:
      object: zscaler.scim_group
      field: group_name
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
      runtimeContextOwner: zscaler
      riskDecisionOwner: zscaler
      runtimeDecisionOwner: zscaler
```

## Support levels

Use explicit support levels:

```text
full:
  target can represent/enforce the requirement with equivalent semantics

partial:
  target can represent part of the requirement, but not fully

conditional:
  target can enforce only if another integration exists

full_vendor_native:
  target can enforce strongly, but with vendor-native semantics

not_supported:
  target cannot represent/enforce this requirement
```

## Fidelity levels

Use explicit fidelity:

```text
high:
  semantic meaning mostly preserved

medium:
  usable but not fully portable or not exactly equivalent

low:
  major downgrade, e.g. app identity becomes IP/port

none:
  requirement is not implemented
```

## Example policy mapping matrix

Policy:

```text
investors may access investor-apps only with MFA, low risk and healthy device
```

Mapping:

```text
Requirement                  Zscaler                         IdP                           Netfilter
------------------------------------------------------------------------------------------------------
subject.role=investors       SCIM/SAML group                  IdP group/role                 not supported
resource.app_group           App Segment Group                App assignment partial         IP/CIDR downgrade
auth.mfa                     SAML/OIDC auth context           native MFA                     not supported
subject.risk.level=low       Zscaler User Risk delegated      external claim conditional     not supported
device.posture=healthy       Zscaler Posture delegated        MDM integration conditional    not supported
effect=allow                 Access Policy                   token issuance partial         allow flow/IP rule
```

## Netfilter example

Netfilter is useful to expose semantic downgrade.

```yaml
apiVersion: kernloom.io/v1
kind: AdapterCapabilityManifest
metadata:
  adapter: netfilter
capabilities:
  - id: netfilter.network.src_ip
    requirementType: network_match
    canonicalObject: network.src_ip
    targetObject: nftables.src_ip
    support: full
  - id: netfilter.network.dst_ip
    requirementType: network_match
    canonicalObject: network.dst_ip
    targetObject: nftables.dst_ip
    support: full
  - id: netfilter.network.port
    requirementType: network_match
    canonicalObject: network.dst_port
    targetObject: nftables.dst_port
    support: full
  - id: netfilter.resource.app_group
    requirementType: resource_match
    canonicalObject: resource.application_group
    targetObject: nftables.ip_set
    support: partial
    downgrade: application_group_to_ip_set
  - id: netfilter.subject.role
    requirementType: subject_match
    canonicalObject: subject.role
    support: not_supported
```

## Compiler behavior

The compiler must:

1. Extract requirements.
2. Query capability manifests.
3. Apply requirement mappings.
4. Build target plans.
5. Produce reports.
6. Fail or warn depending on policy strictness.

## Strictness modes

```text
strict:
  all requirements must be enforced with high fidelity

allow_partial_with_approval:
  partial mapping allowed with explicit approval

observe_only:
  generate plan/report but do not deploy

vendor_delegation_allowed:
  vendor-native runtime delegation is allowed if declared
```

## Key invariant

Requirement Mapping must be explicit, versioned and reviewable.

It must not be hidden only in adapter code.
