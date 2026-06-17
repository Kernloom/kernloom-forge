// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package capability

// Domain tokens answer "which domain owns this concern?"
// Every OwnerRef.Owner field must be one of these values.
const (
	// DomainKernloom — this concern is owned by Kernloom's own components.
	DomainKernloom = "kernloom"

	// DomainVendor — this concern is owned by the target's vendor systems.
	// The vendor's internal components make decisions, hold state, or enforce
	// without Kernloom direct control or observability per operation.
	DomainVendor = "vendor"
)

// Kernloom component names for OwnerRef.Component.
// These are functional names for Kernloom subsystems, independent of how
// they are deployed (KLIQ locally, Correlate centrally, or combined).
const (
	// ComponentPMS — Policy Management System (Forge). Authors, versions,
	// and publishes enterprise policy intent.
	ComponentPMS = "pms"

	// ComponentPIPs — Policy Information Points. Collect signals and context
	// from EDR, IdP, SIEM, CMDB, and local eBPF telemetry.
	ComponentPIPs = "pips"

	// ComponentRiskEngine — aggregates PIP signals into risk facts
	// (subject.risk.level, device.risk.level). Separate from the PDP that
	// makes the policy decision using those facts.
	ComponentRiskEngine = "risk-engine"

	// ComponentRuntimePDP — evaluates enterprise policy at runtime and
	// decides allow / deny / restrict. Consumes risk facts from the Risk Engine.
	ComponentRuntimePDP = "runtime-pdp"

	// ComponentConfigPDP — validates proposed config changes during CI/PR.
	ComponentConfigPDP = "config-pdp"

	// ComponentActionBroker — routes runtime decisions to target adapters,
	// enforces TTL, and coordinates auto-revert.
	ComponentActionBroker = "action-broker"

	// ComponentEBPFXDP — XDP eBPF programs (KLShield early-drop path).
	ComponentEBPFXDP = "ebpf-xdp"

	// ComponentEBPFTC — TC eBPF programs (KLShield rate-limit / redirect path).
	ComponentEBPFTC = "ebpf-tc"

	// ComponentNftables — nftables kernel tables (netfilter static rules).
	ComponentNftables = "nftables"
)

// Vendor component names for OwnerRef.Component.
// These are functional names, not product-specific. "controller" works for
// OpenZiti but also for any ZTNA controller. "token-service" works for any IdP.
const (
	// ComponentVendorController — vendor's central control plane or policy
	// engine (e.g. OpenZiti Controller, Okta tenant, Entra tenant).
	ComponentVendorController = "controller"

	// ComponentVendorEdgeRouter — vendor's data-plane enforcement edge
	// (e.g. OpenZiti Edge Router, Zscaler enforcement node).
	ComponentVendorEdgeRouter = "edge-router"

	// ComponentVendorTokenService — vendor's authentication / token issuance
	// enforcement (IdP: denies or issues tokens based on CA policy).
	ComponentVendorTokenService = "token-service"

	// ComponentVendorPostureService — vendor's posture evaluation service
	// (e.g. OpenZiti posture checks, MDM compliance engine).
	ComponentVendorPostureService = "posture-service"
)
