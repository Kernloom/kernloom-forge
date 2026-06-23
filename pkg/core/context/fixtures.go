// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package context

import "time"

// EnterpriseContextFixtureSnapshot returns a deterministic ContextSnapshot
// that exercises the P1 PIP path without depending on live vendor systems.
func EnterpriseContextFixtureSnapshot(now time.Time) ContextSnapshot {
	if now.IsZero() {
		now = time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	}
	subject := EntityRef{Type: "subject", Ref: "subject:alice@example.com"}
	device := EntityRef{Type: "device", Ref: "device:alice-laptop"}
	resource := EntityRef{Type: "resource", Ref: "resource:admin-controller"}
	session := EntityRef{Type: "session", Ref: "session:edge-01"}
	return ContextSnapshot{
		ID:                     "fixture-enterprise-idp-cmdb-posture",
		SnapshotAt:             now,
		ValidUntil:             now.Add(30 * time.Minute),
		ContextRegistryVersion: "0.2.0",
		Facts: []ContextFact{
			fixtureFact("subject.id", "alice@example.com", subject, "idp-fixture", "identity_provider", now),
			fixtureFact("subject.type", "user", subject, "idp-fixture", "identity_provider", now),
			fixtureFact("subject.role", "kernloom-admin", subject, "idp-fixture", "identity_provider", now),
			fixtureFact("subject.group", []string{"kernloom-admins", "security"}, subject, "idp-fixture", "identity_provider", now),
			fixtureFact("session.authentication.strength", "mfa", session, "idp-fixture", "identity_provider", now),
			fixtureFact("device.posture.status", "unhealthy", device, "posture-pip-fixture", "posture_pip", now),
			fixtureFact("subject.behavior.anomaly_detected", true, subject, "network-pip-fixture", "network_pip", now),
			fixtureFact("resource.id", "admin-controller", resource, "cmdb-fixture", "cmdb", now),
			fixtureFact("resource.type", "endpoint", resource, "cmdb-fixture", "cmdb", now),
			fixtureFact("resource.data_class", "restricted", resource, "cmdb-fixture", "cmdb", now),
			fixtureFact("resource.criticality", "critical", resource, "cmdb-fixture", "cmdb", now),
			fixtureFact("resource.environment", "production", resource, "cmdb-fixture", "cmdb", now),
		},
		VendorAssessments: []VendorAssessment{
			fixtureVendorAssessment("posture_provider", "posture_provider.device_posture_result", "fail", device, "device.posture.status", now),
			fixtureVendorAssessment("idp", "idp.groups", []string{"kernloom-admins", "security"}, subject, "subject.group", now),
			fixtureVendorAssessment("cmdb", "cmdb.asset_criticality", "tier-0", resource, "resource.criticality", now),
		},
		EntityLinks: []EntityLink{{
			Subject: subject,
			Aliases: []EntityRef{
				{Type: "network_identity", Ref: "network:alice"},
				{Type: "idp_user", Ref: "idp:alice@example.com"},
				{Type: "device", Ref: "device:alice-laptop"},
			},
			Confidence:   0.98,
			Approved:     true,
			Source:       "fixture-entity-resolution",
			ObservedAt:   now,
			EvidenceRefs: []string{"vendor-assessment:idp.groups", "vendor-assessment:posture_provider.device_posture_result"},
		}},
		PIPHealth: []PIPHealth{
			fixturePIPHealth("posture-pip-fixture", now),
			fixturePIPHealth("network-pip-fixture", now),
			fixturePIPHealth("idp-fixture", now),
			fixturePIPHealth("cmdb-fixture", now),
		},
	}
}

func fixtureFact(key string, value any, entity EntityRef, adapter, sourceType string, now time.Time) ContextFact {
	return ContextFact{
		Key:       key,
		Value:     value,
		EntityRef: entity,
		Provenance: Provenance{
			SourceAdapter:  adapter,
			SourceType:     sourceType,
			PIPInstanceID:  adapter + "-01",
			CollectedAt:    now,
			MappingVersion: "fixture-mapping@1.0.0",
		},
		Quality:    DataQuality{Confidence: 0.95, MaxAge: 30 * time.Minute},
		ObservedAt: now.Add(-2 * time.Minute),
		ValidUntil: now.Add(28 * time.Minute),
		Status:     FactStatusKnown,
	}
}

func fixtureVendorAssessment(vendor, key string, value any, entity EntityRef, mappedTo string, now time.Time) VendorAssessment {
	return VendorAssessment{
		Vendor:    vendor,
		Key:       key,
		Value:     value,
		EntityRef: entity,
		MappedTo:  mappedTo,
		Provenance: Provenance{
			SourceAdapter:  vendor + "-fixture",
			SourceType:     "pip_fixture",
			PIPInstanceID:  vendor + "-fixture-01",
			CollectedAt:    now,
			MappingVersion: "fixture-mapping@1.0.0",
		},
		ObservedAt: now.Add(-2 * time.Minute),
	}
}

func fixturePIPHealth(adapter string, now time.Time) PIPHealth {
	return PIPHealth{
		SourceAdapter:   adapter,
		Status:          "healthy",
		Healthy:         true,
		EventLagSeconds: 0.25,
		LastSeenAt:      now,
		Details:         "fixture PIP is replaying deterministic data",
	}
}
