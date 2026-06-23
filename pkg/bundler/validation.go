// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundler

import (
	"fmt"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/core/response"
	registries "github.com/kernloom/kernloom-registries"
)

func validationSnapshot(snapshot contracts.RegistrySnapshot) (contracts.RegistrySnapshot, error) {
	if snapshot.Ref.Name != "" {
		return snapshot, nil
	}
	embedded, err := registries.EmbeddedSnapshot()
	if err != nil {
		return contracts.RegistrySnapshot{}, fmt.Errorf("bundler: load registry snapshot for validation: %w", err)
	}
	return embedded, nil
}

func validateBuiltRuntimePolicyPack(pack contracts.RuntimePolicyPack, snapshot contracts.RegistrySnapshot) error {
	if snapshot.Ref.Name == "" {
		return fmt.Errorf("bundler: registry snapshot is required for runtime pack validation")
	}
	if err := response.ValidateRuntimeReferences(pack.Spec.DetectionRules, pack.Spec.ResponseRules, pack.Spec.AlertRoutes, snapshot); err != nil {
		return fmt.Errorf("bundler: response IR validation: %w", err)
	}
	capabilities := capabilityEntries(snapshot)
	contractsByID := actionContracts(snapshot)
	for _, rule := range pack.Spec.Rules {
		if err := validateRuntimeAction(rule.Then, capabilities, contractsByID); err != nil {
			return fmt.Errorf("bundler: runtime rule %q: %w", rule.ID, err)
		}
	}
	if pack.Spec.AutonomyLifecycle != nil {
		for _, hold := range pack.Spec.AutonomyLifecycle.Hold {
			if err := validateRuntimeAction(hold.Action, capabilities, contractsByID); err != nil {
				return fmt.Errorf("bundler: autonomy hold %q: %w", hold.ID, err)
			}
		}
	}
	for _, rule := range pack.Spec.ResponseRules {
		for i, action := range rule.Then {
			if err := validateRuntimeResponseActionContract(action, capabilities, contractsByID); err != nil {
				return fmt.Errorf("bundler: response rule %q action[%d]: %w", rule.ID, i, err)
			}
		}
	}
	return nil
}

func normalizeBuiltRuntimePolicyPackContracts(pack *contracts.RuntimePolicyPack, snapshot contracts.RegistrySnapshot) error {
	if pack == nil {
		return nil
	}
	capabilities := capabilityEntries(snapshot)
	contractsByID := actionContracts(snapshot)
	for i := range pack.Spec.Rules {
		contract, ok := contractForRuntimeAction(pack.Spec.Rules[i].Then, capabilities, contractsByID)
		if !ok {
			continue
		}
		normalizeRuntimeActionContractParams(&pack.Spec.Rules[i].Then, contract)
	}
	if pack.Spec.AutonomyLifecycle != nil {
		for i := range pack.Spec.AutonomyLifecycle.Hold {
			contract, ok := contractForRuntimeAction(pack.Spec.AutonomyLifecycle.Hold[i].Action, capabilities, contractsByID)
			if !ok {
				continue
			}
			normalizeRuntimeActionContractParams(&pack.Spec.AutonomyLifecycle.Hold[i].Action, contract)
		}
	}
	for i := range pack.Spec.ResponseRules {
		for j := range pack.Spec.ResponseRules[i].Then {
			contract, ok := contractForResponseAction(pack.Spec.ResponseRules[i].Then[j], capabilities, contractsByID)
			if !ok {
				continue
			}
			normalizeResponseActionContractParams(&pack.Spec.ResponseRules[i].Then[j], contract)
		}
	}
	return nil
}

func validateRuntimeAction(action contracts.RuntimeActionSpec, capabilities map[string]contracts.CapabilityEntry, contractsByID map[string]contracts.RuntimeActionContractEntry) error {
	if strings.TrimSpace(action.Capability) == "" {
		return fmt.Errorf("action capability is required")
	}
	capability, ok := capabilities[action.Capability]
	if !ok {
		return fmt.Errorf("unknown runtime action capability %q", action.Capability)
	}
	if !capability.RuntimeAction {
		return fmt.Errorf("capability %q is not a runtime action", action.Capability)
	}
	if capability.Effect == "grant" {
		return fmt.Errorf("capability %q grants access and is not allowed in runtime packs", action.Capability)
	}
	contractID := capability.ActionContract
	if contractID == "" {
		contractID = action.Capability
	}
	contract, ok := contractsByID[contractID]
	if !ok {
		return fmt.Errorf("capability %q references unknown action contract %q", action.Capability, contractID)
	}
	if !contract.RuntimeAllowed {
		return fmt.Errorf("action contract %q is not runtime allowed", contract.ID)
	}
	if contract.CanGrantAccess {
		return fmt.Errorf("action contract %q can grant access and is not allowed in runtime packs", contract.ID)
	}
	if contract.RequiresTTL && action.TTL.Duration <= 0 {
		return fmt.Errorf("action contract %q requires ttl", contract.ID)
	}
	if maxTTL, err := parseOptionalDuration(contract.MaxTTL); err != nil {
		return fmt.Errorf("action contract %q maxTTL: %w", contract.ID, err)
	} else if maxTTL > 0 && action.TTL.Duration > maxTTL {
		return fmt.Errorf("action contract %q ttl %s exceeds maxTTL %s", contract.ID, action.TTL.Duration, maxTTL)
	}
	if err := validateContractObligations(contract, action.TTL.Duration, action.Params); err != nil {
		return fmt.Errorf("action contract %q: %w", contract.ID, err)
	}
	return nil
}

func validateRuntimeResponseActionContract(
	action contracts.RuntimeResponseAction,
	capabilities map[string]contracts.CapabilityEntry,
	contractsByID map[string]contracts.RuntimeActionContractEntry,
) error {
	contract, ok := contractForResponseAction(action, capabilities, contractsByID)
	if !ok {
		return nil
	}
	if contract.CanGrantAccess {
		return fmt.Errorf("action contract %q can grant access and is not allowed in runtime packs", contract.ID)
	}
	if !contract.RuntimeAllowed && contract.Effect != "notify" {
		return fmt.Errorf("action contract %q is not runtime allowed", contract.ID)
	}
	if contract.RequiresTTL && action.TTL.Duration <= 0 {
		return fmt.Errorf("action contract %q requires ttl", contract.ID)
	}
	if maxTTL, err := parseOptionalDuration(contract.MaxTTL); err != nil {
		return fmt.Errorf("action contract %q maxTTL: %w", contract.ID, err)
	} else if maxTTL > 0 && action.TTL.Duration > maxTTL {
		return fmt.Errorf("action contract %q ttl %s exceeds maxTTL %s", contract.ID, action.TTL.Duration, maxTTL)
	}
	if err := validateContractObligations(contract, action.TTL.Duration, action.Params); err != nil {
		return fmt.Errorf("action contract %q: %w", contract.ID, err)
	}
	return nil
}

func contractForRuntimeAction(
	action contracts.RuntimeActionSpec,
	capabilities map[string]contracts.CapabilityEntry,
	contractsByID map[string]contracts.RuntimeActionContractEntry,
) (contracts.RuntimeActionContractEntry, bool) {
	capability, ok := capabilities[action.Capability]
	if !ok {
		return contracts.RuntimeActionContractEntry{}, false
	}
	contractID := capability.ActionContract
	if contractID == "" {
		contractID = action.Capability
	}
	contract, ok := contractsByID[contractID]
	return contract, ok
}

func contractForResponseAction(
	action contracts.RuntimeResponseAction,
	capabilities map[string]contracts.CapabilityEntry,
	contractsByID map[string]contracts.RuntimeActionContractEntry,
) (contracts.RuntimeActionContractEntry, bool) {
	contractID := action.ID
	if capability, ok := capabilities[action.ID]; ok && capability.ActionContract != "" {
		contractID = capability.ActionContract
	}
	contract, ok := contractsByID[contractID]
	return contract, ok
}

func normalizeRuntimeActionContractParams(action *contracts.RuntimeActionSpec, contract contracts.RuntimeActionContractEntry) {
	if action.Params == nil {
		action.Params = map[string]any{}
	}
	normalizeContractParams(action.Params, contract)
}

func normalizeResponseActionContractParams(action *contracts.RuntimeResponseAction, contract contracts.RuntimeActionContractEntry) {
	if action.Params == nil {
		action.Params = map[string]any{}
	}
	normalizeContractParams(action.Params, contract)
}

func normalizeContractParams(params map[string]any, contract contracts.RuntimeActionContractEntry) {
	if contract.RequiresAudit {
		params["audit_required"] = true
	}
	if contract.RequiresLease {
		params["lease_required"] = true
	}
	if contract.AutoRevert != "" {
		params["auto_revert"] = contract.AutoRevert
	}
	if contract.RequiredConfidence != "" {
		params["required_confidence"] = contract.RequiredConfidence
	}
	if len(contract.AllowedDecisionSources) > 0 && params["decision_source"] == nil {
		params["decision_source"] = defaultDecisionSource(contract.AllowedDecisionSources)
	}
}

func defaultDecisionSource(allowed []string) string {
	for _, source := range allowed {
		if source == "kliq" {
			return source
		}
	}
	if len(allowed) > 0 {
		return allowed[0]
	}
	return ""
}

func validateContractObligations(contract contracts.RuntimeActionContractEntry, ttl time.Duration, params map[string]any) error {
	if contract.RequiresApproval && !hasAnyParam(params, "approval_ref", "approval_id", "approved_by") {
		return fmt.Errorf("requires approval reference")
	}
	if contract.RequiresAudit && !boolParam(params, "audit_required") {
		return fmt.Errorf("requires audit metadata")
	}
	if contract.RequiresLease && !boolParam(params, "lease_required") {
		return fmt.Errorf("requires lease metadata")
	}
	if contract.AutoRevert != "" {
		if !contract.Reversible {
			return fmt.Errorf("requires auto-revert but action is not reversible")
		}
		if ttl <= 0 {
			return fmt.Errorf("requires auto-revert with ttl")
		}
		if strings.TrimSpace(fmt.Sprint(params["auto_revert"])) == "" {
			return fmt.Errorf("requires auto-revert metadata")
		}
	}
	if contract.RequiredConfidence != "" && strings.TrimSpace(fmt.Sprint(params["required_confidence"])) == "" {
		return fmt.Errorf("requires confidence metadata")
	}
	if len(contract.AllowedDecisionSources) > 0 {
		source := strings.TrimSpace(fmt.Sprint(params["decision_source"]))
		if source == "" {
			return fmt.Errorf("requires decision_source")
		}
		if !stringIn(source, contract.AllowedDecisionSources) {
			return fmt.Errorf("decision_source %q is not allowed", source)
		}
	}
	return nil
}

func boolParam(params map[string]any, key string) bool {
	if params == nil {
		return false
	}
	switch v := params[key].(type) {
	case bool:
		return v
	case string:
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "true" || v == "yes" || v == "1"
	default:
		return fmt.Sprint(v) == "true"
	}
}

func hasAnyParam(params map[string]any, keys ...string) bool {
	for _, key := range keys {
		if strings.TrimSpace(fmt.Sprint(params[key])) != "" && fmt.Sprint(params[key]) != "<nil>" {
			return true
		}
	}
	return false
}

func stringIn(value string, values []string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func capabilityEntries(snapshot contracts.RegistrySnapshot) map[string]contracts.CapabilityEntry {
	out := make(map[string]contracts.CapabilityEntry, len(snapshot.Capabilities))
	for _, capability := range snapshot.Capabilities {
		out[capability.ID] = capability
	}
	return out
}

func actionContracts(snapshot contracts.RegistrySnapshot) map[string]contracts.RuntimeActionContractEntry {
	out := make(map[string]contracts.RuntimeActionContractEntry, len(snapshot.ActionContracts))
	for _, contract := range snapshot.ActionContracts {
		out[contract.ID] = contract
	}
	return out
}

func parseOptionalDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}
