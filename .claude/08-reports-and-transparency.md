# 08 Reports and Transparency

## Goal

Kernloom must make policy translation transparent.

Reports are not optional. They are the primary way to show what the platform actually did.

## Required reports

- Enforcement Coverage Report
- Delegation Report
- Semantic Downgrade Report
- Config PDP Validation Report
- Decision Receipt
- Enforcement Receipt
- Drift Report
- Change Proposal Report

## Enforcement Coverage Report

Shows which requirements were implemented per target.

```yaml
apiVersion: kernloom.io/v1
kind: EnforcementCoverageReport
metadata:
  sourcePolicy: investor-apps-access
targets:
  - target: zscaler
    status: deployable
    coverage: high
    implementedRequirements:
      - req-001
      - req-002
      - req-003
      - req-004
      - req-005
    delegatedRequirements:
      - req-004
      - req-005
  - target: idp
    status: partial
    coverage: medium
    implementedRequirements:
      - req-001
      - req-003
    missingRequirements:
      - req-004
      - req-005
```

## Delegation Report

Shows who owns what.

```yaml
apiVersion: kernloom.io/v1
kind: DelegationReport
metadata:
  sourcePolicy: investor-apps-access
targets:
  - target: zscaler
    status: runtime_delegated
    ownership:
      intentOwner: enterprise-pms
      runtimeContextOwner: zscaler
      riskDecisionOwner: zscaler
      runtimeDecisionOwner: zscaler
      policyEvaluationOwner: zscaler
      enforcementOwner: zscaler
      configOwner: git/config-pipeline
    delegatedRequirements:
      - req-004
      - req-005
  - target: idp
    status: partial_enforcement
    ownership:
      intentOwner: enterprise-pms
      runtimeContextOwner: idp
      riskDecisionOwner: not_available_in_mvp
      runtimeDecisionOwner: idp_for_auth_only
      policyEvaluationOwner: idp
      enforcementOwner: idp
```

## Semantic Downgrade Report

Shows where meaning was weakened.

```yaml
apiVersion: kernloom.io/v1
kind: SemanticDowngradeReport
metadata:
  sourcePolicy: investor-apps-access
downgrades:
  - target: netfilter
    requirement: req-002
    original: resource.application_group = investor-apps
    mappedTo: ip_set
    downgrade: application_group_to_ip_set
    severity: high
  - target: idp
    requirement: req-004
    original: subject.risk.level = low
    mappedTo: none
    downgrade: condition_not_enforceable
    severity: high
  - target: zscaler
    requirement: req-004
    original: subject.risk.level = low
    mappedTo: zscaler.user_risk
    downgrade: vendor_native_semantics
    severity: medium
```

## Config PDP Validation Report

Shows whether durable config may be deployed.

```yaml
apiVersion: kernloom.io/v1
kind: ConfigPDPValidationReport
metadata:
  sourcePolicy: investor-apps-access
decision:
  result: allow_with_warnings
checks:
  - name: source_policy_exists
    result: pass
  - name: all_requirements_mapped_or_declared
    result: pass
  - name: delegated_runtime_decision_declared
    result: pass
  - name: semantic_downgrade_report_exists
    result: pass
  - name: required_approval_present
    result: pass
warnings:
  - target: zscaler
    message: Risk and posture evaluation are delegated to Zscaler.
  - target: idp
    message: Risk and posture are not enforceable in IdP MVP.
```

## Decision Receipt

Runtime PDPs must emit receipts.

```yaml
apiVersion: kernloom.io/v1
kind: DecisionReceipt
metadata:
  id: dec-001
spec:
  pdp: kliq-runtime-pdp
  policyPack: runtime-pack-123
  decision: deny
  subject: user:alice
  resource: app:investor-apps
  reason:
    - subject.risk.level = high
  inputs:
    - riskAssessment:risk-001
    - signal:klshield-flow-987
  ttl: 30m
```

## Enforcement Receipt

PEPs/adapters must emit enforcement receipts.

```yaml
apiVersion: kernloom.io/v1
kind: EnforcementReceipt
metadata:
  id: enf-001
spec:
  adapter: netfilter
  decisionRef: dec-001
  action: deny_flow
  result: applied
  ttl: 30m
  autoRevert: true
```

## Drift Report

Shows where target config differs from approved desired state.

```yaml
apiVersion: kernloom.io/v1
kind: DriftReport
metadata:
  target: zscaler
spec:
  desiredStateRef: git:commit:abc123
  observedAt: "2026-06-12T12:00:00Z"
  drift:
    - object: zscaler.access_policy.allow-investors
      field: conditions.device_posture
      desired: compliant
      actual: missing
      severity: high
```

## Report invariant

Every compiled policy must produce at least:

- coverage report
- delegation report
- downgrade report

Even if nothing is deployed.

## Source-of-Truth and PAP Report

Kernloom should report whether a deployment plan came from the approved Enterprise PAP.

A Source-of-Truth report answers:

- Which Git repository and commit produced this plan?
- Which PR approved the change?
- Which CODEOWNERS or reviewers approved it?
- Which Config PDP decision allowed it?
- Which reports were attached to the PR?
- Did Forge consume the approved branch or an unapproved source?
- Did a target drift away from the approved Git state?

Example:

```yaml
sourceOfTruth:
  enterprisePap: git
  repository: kernloom-policies
  branch: main
  commit: 9f3a12c
  pullRequest: 184
  approvedBy:
    - security-architecture
    - app-owner-investor-apps
  configPdpDecision: allow_with_warnings
  forgeRelease: 2026.06.12-001
```

This prevents Forge, adapters or vendor control planes from becoming uncontrolled parallel PAPs.

## Target Integration Report

Kernloom should report the integration pattern for each target.

```yaml
apiVersion: kernloom.io/v1
kind: TargetIntegrationReport
metadata:
  target: zscaler
spec:
  pattern: vendor_config_only_with_readback
  roles:
    pap: zscaler-admin-api
    pdp: zscaler-runtime-pdp
    pep: zscaler-enforcement
    pip: zscaler-read-adapter
  ownership:
    validationOwner: kernloom-config-pdp
    deploymentOwner: platform-pipeline
    runtimeDecisionOwner: zscaler
    actualStateOwner: zscaler-read-adapter
  notes:
    - Kernloom validates durable config before deployment.
    - Zscaler owns live runtime evaluation and enforcement.
    - Drift detection depends on read adapter coverage.
```

## Drift Ownership Report

Drift reports must distinguish who deployed, who owns desired state, and who observed actual state.

```yaml
apiVersion: kernloom.io/v1
kind: DriftOwnershipReport
metadata:
  target: zscaler
spec:
  desiredStateOwner: git-enterprise-pap
  validationOwner: kernloom-config-pdp
  deploymentOwner: platform-pipeline
  actualStateSource: zscaler-read-adapter
  runtimeOwner: zscaler
  remediationMode: proposal_only
```

This prevents false assumptions that Kernloom owns deployment or runtime when it only validates and observes.
