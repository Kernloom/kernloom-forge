// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package capability

// Canonical owner tokens for OwnershipDeclaration fields.
//
// # What these tokens are
//
// Owner tokens are role identifiers that answer "which domain owns this
// concern?" — Kernloom's domain or the vendor's domain. They are NOT
// component names. The manifest's metadata.name already identifies which
// specific component (openziti, klshield, netfilter, idp) is involved.
//
// All OwnershipDeclaration fields use these tokens, including enforcementOwner
// and runtimeStateOwner. This makes reports consistent and comparable across
// all manifests regardless of the target type.
//
// # Choosing the right token
//
//   - kernloom-*     Kernloom owns this concern. Use the most specific
//                    sub-token (pips, risk-engine, runtime-pdp) when the
//                    distinction matters; use kernloom for static/compile-time
//                    concerns where the sub-role is not relevant.
//
//   - vendor         The target's own vendor system owns this concern.
//                    Runtime context, decision, evaluation and enforcement
//                    all stay inside the vendor platform.
//
//   - git-pipeline   An external CI/CD pipeline owns config deployment.
//
// # Typical patterns
//
//   Variant A — config-only / runtime delegated to vendor:
//     runtimeContextOwner:   vendor
//     riskDecisionOwner:     vendor
//     runtimeDecisionOwner:  vendor
//     policyEvaluationOwner: vendor
//     enforcementOwner:      vendor
//     configOwner:           kernloom
//
//   Variant B — Kernloom runtime PDP + vendor enforcement:
//     runtimeContextOwner:   kernloom-pips
//     riskDecisionOwner:     kernloom-runtime-pdp
//     runtimeDecisionOwner:  kernloom-runtime-pdp
//     policyEvaluationOwner: vendor          (vendor still evaluates its own policies)
//     enforcementOwner:      vendor
//     runtimeStateOwner:     vendor
//     configOwner:           kernloom
//
//   Local PEP (kernloom-native, e.g. klshield, netfilter):
//     runtimeContextOwner:   kernloom-pips   (or kernloom for static config)
//     riskDecisionOwner:     kernloom-runtime-pdp
//     runtimeDecisionOwner:  kernloom-runtime-pdp
//     policyEvaluationOwner: kernloom-runtime-pdp
//     enforcementOwner:      kernloom
//     runtimeStateOwner:     kernloom
//     configOwner:           kernloom
const (
	// OwnerEnterprisePMS is Kernloom's policy management plane (Forge).
	// Always the intentOwner. Never a runtime or enforcement owner.
	OwnerEnterprisePMS = "enterprise-pms"

	// OwnerKernloomPIPs is Kernloom's PIP layer: the adapters and local
	// agents that collect signals and context. Fulfilled by KLIQ's
	// telemetry function locally, or dedicated PIP adapters centrally.
	OwnerKernloomPIPs = "kernloom-pips"

	// OwnerKernloomRiskEngine is Kernloom's risk evaluation component.
	// Aggregates PIP signals into risk facts. Fulfilled by KLIQ's local
	// lightweight evaluator, Correlate's central engine, or both.
	OwnerKernloomRiskEngine = "kernloom-risk-engine"

	// OwnerKernloomRuntimePDP is Kernloom's runtime policy decision point.
	// Makes per-request allow/deny/restrict decisions. Fulfilled by KLIQ
	// locally, Correlate centrally, or both in a hybrid deployment.
	OwnerKernloomRuntimePDP = "kernloom-runtime-pdp"

	// OwnerKernloom is the shorthand for any Kernloom-owned concern where
	// distinguishing between PIP, risk engine, and PDP is not necessary —
	// e.g. static/compile-time enforcement (netfilter rules, nftables sets)
	// or enforcement by a Kernloom-native agent (KLShield eBPF programs).
	OwnerKernloom = "kernloom"

	// OwnerVendor indicates that the vendor's own systems own this concern:
	// context collection, risk evaluation, runtime decision, policy
	// evaluation, and enforcement all stay inside the vendor platform.
	// Examples: OpenZiti controller, IdP conditional access, Zscaler.
	OwnerVendor = "vendor"

	// OwnerGitPipeline indicates that an external CI/CD pipeline owns
	// configuration deployment. Kernloom validates but does not deploy.
	OwnerGitPipeline = "git-pipeline"
)
