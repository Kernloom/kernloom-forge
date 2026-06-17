# 11 AI Implementation Backlog

## P-1: GitOps Enterprise PAP foundation

Implement repository conventions and metadata for Git as the durable Enterprise PAP.

Acceptance:

- Policies, registries, adapter manifests and requirement mappings live in Git.
- PR validation can run schema validation, compile dry-run, Config PDP checks and report generation.
- Every compiled artifact contains source-of-truth metadata: repository, branch, commit, PR and approval references.
- Forge can consume an approved branch or release artifact.
- Forge UI, if present, creates PRs and does not directly mutate durable policy truth.

## P0: Create core schemas

Implement:

```text
pkg/core/intent
pkg/core/requirement
pkg/core/context
pkg/core/capability
pkg/core/mapping
pkg/core/report
```

Acceptance:

- AccessPolicy can be parsed from YAML.
- RequirementSet can be generated.
- CapabilityManifest can be loaded.
- RequirementMapping can be loaded.

## P1: Requirement extractor

Implement:

```text
AccessPolicy → RequirementSet
```

Acceptance:

Input policy:

```text
investors → investor-apps, MFA, risk low, device healthy
```

Output requirements:

```text
subject.role == investors
resource.application_group == investor-apps
auth_strength >= mfa
subject.risk.level == low
device.posture.status == healthy
effect == allow
```

## P2: Capability matcher

Implement:

```text
RequirementSet + AdapterCapabilities → CapabilityMatchResult
```

Acceptance:

- Zscaler shows high coverage.
- IdP shows partial coverage.
- Netfilter shows semantic downgrade.

## P3: Requirement mapping engine

Implement:

```text
RequirementSet + RequirementMapping → TargetPlanDraft
```

Acceptance:

- Generates target-specific mapping result.
- Missing requirements are not dropped.
- Vendor-native mappings are marked delegated.

## P4: Reports

Implement:

- EnforcementCoverageReport
- DelegationReport
- SemanticDowngradeReport

Acceptance:

Every compile run emits all three reports.

## P5: Config PDP

Implement Config PDP as deployment validator.

Checks:

- source policy exists
- all requirements mapped or explicitly declared missing
- delegation declared
- semantic downgrade report exists
- required approvals present
- no runtime-only action in config path
- no config write without approved Git source of truth

## P6: Zscaler dry-run target

Implement a Zscaler TargetPlan schema and dry-run translator.

Do not call real Zscaler API first.

Acceptance:

Generic policy creates:

- app segment group plan
- access policy plan
- risk/posture delegation declaration

## P7: IdP dry-run target

Implement IdP target plan showing partial enforcement.

Acceptance:

- group/role mapping
- MFA conditional access mapping
- risk/posture missing unless external claims are configured

## P8: Netfilter/KLShield feasibility target

Implement mapping for local PEPs.

Acceptance:

- network tuple requirements supported
- identity/app-group requirements shown as unsupported or downgraded

## P9: Runtime decision receipts

Implement receipts for local runtime decisions.

Acceptance:

- KLIQ decision emits DecisionReceipt
- enforcement emits EnforcementReceipt
- TTL and auto-revert metadata included

## P10: Change proposal model

Implement:

```text
RuntimeFinding → ChangeProposal
```

Acceptance:

Proposal contains:

- evidence
- policy delta
- config delta
- target impact
- required approvals

## P11: PIP adapter model

Implement PIP contract.

Acceptance:

- IdP PIP emits subject groups
- Zscaler PIP emits vendor assessments
- KLShield PIP emits flow signals

## P12: Adapter SDK validation

Implement adapter package validator.

Acceptance:

- manifest schema validation
- capability validation
- mapping validation
- conformance test runner stub

## Suggested first test case

Create one golden test:

```text
Policy: investors may access investor-apps only with MFA, low risk and healthy device
Targets: zscaler, idp, netfilter
```

Expected output:

- Zscaler: deployable, runtime delegated
- IdP: partial, risk/posture missing
- Netfilter: partial/downgraded, identity/app semantics missing
- Reports: coverage, delegation, downgrade

## Key architecture decisions to encode as tests

1. A missing requirement must never disappear.
2. A runtime delegated requirement must be declared.
3. A config deployment plan must pass Config PDP.
4. A runtime action must have TTL.
5. Runtime action adapters must not write durable config.
6. PIP values must include source/freshness/confidence.
7. Vendor-native risk must not automatically equal enterprise risk.
8. Adapter mapping must be explicit, not hardcoded only.

9. Durable policy truth must come from the Enterprise PAP.
10. Forge must not publish a durable config plan that cannot be traced to an approved Git commit.
11. A runtime finding may create a PR, but may not directly create durable config.
