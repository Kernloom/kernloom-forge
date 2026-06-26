// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"strings"

	contracts "github.com/kernloom/kernloom-contracts"
	coreintent "github.com/kernloom/kernloom-forge/pkg/core/intent"
)

func runtimeAccessPoliciesFromComposition(comp *policyComposition) []contracts.RuntimeAccessPolicy {
	if comp == nil {
		return nil
	}
	source := comp.SourceName()
	policies := make([]contracts.RuntimeAccessPolicy, 0, len(comp.AccessPolicies))
	for _, policy := range comp.AccessPolicies {
		runtimePolicy, ok := runtimeAccessPolicyFromIntent(policy, source)
		if ok {
			policies = append(policies, runtimePolicy)
		}
	}
	return policies
}

func runtimeAccessPolicyFromIntent(policy *coreintent.AccessPolicy, source string) (contracts.RuntimeAccessPolicy, bool) {
	if policy == nil {
		return contracts.RuntimeAccessPolicy{}, false
	}
	id := strings.TrimSpace(policy.Metadata.Name)
	if id == "" {
		return contracts.RuntimeAccessPolicy{}, false
	}
	if strings.TrimSpace(source) == "" {
		source = id
	}
	effect := strings.TrimSpace(policy.Spec.Effect)
	if effect == "" {
		effect = "allow"
	}
	conditions := make([]contracts.RuntimeAccessCondition, 0, len(policy.Spec.Conditions))
	for _, condition := range policy.Spec.Conditions {
		conditions = append(conditions, contracts.RuntimeAccessCondition{
			ID:       condition.ID,
			Type:     condition.Type,
			Signal:   condition.Signal,
			Operator: condition.Operator,
			Value:    condition.Value,
			CEL:      condition.CEL,
		})
	}
	return contracts.RuntimeAccessPolicy{
		ID:          id,
		Description: policy.Metadata.Labels["description"],
		Subject: contracts.RuntimeAccessSubject{
			Type: policy.Spec.Subject.Type,
			Ref:  policy.Spec.Subject.Ref,
		},
		Action: policy.Spec.Action,
		Resource: contracts.RuntimeAccessResource{
			Type: policy.Spec.Resource.Type,
			Ref:  policy.Spec.Resource.Ref,
		},
		Requirements:  append([]string(nil), policy.Spec.Requirements...),
		Conditions:    conditions,
		Effect:        effect,
		DefaultEffect: "deny",
		Source:        source,
		ReasonCodes:   []string{"access_policy_desired_state"},
	}, true
}
