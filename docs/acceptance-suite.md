# Acceptance Suite

The doc-level acceptance path is intentionally small and mirrors the manual
guide:

```text
Natural Intent
  -> forge intent convert
  -> digest-pinned PolicyIntent
  -> forge compile/export RuntimePolicyPack
  -> KLIQ-readable response, guardrail and gap metadata
  -> enrollment inventory labels visible to node-aware placement
```

The automated coverage lives in:

```text
cmd/forge/doc_acceptance_test.go
internal/api/server_test.go
```

It exercises `examples/policies/manual-edge-access.intent` and asserts that the
compiled RuntimePolicyPack carries:

- DetectionPolicy and ResponsePolicy runtime IR.
- AlertRoute routing.
- Guardrail IR.
- explicit `gap_metadata`.
- previous-action and blast-radius safety metadata.
- action-contract metadata such as audit and auto-revert requirements.
- node inventory labels preserved through enrollment and bundle lookup.

Run it with:

```bash
go test ./cmd/forge -run TestDocAcceptance
go test ./internal/api -run 'TestEnroll|TestNodeAwareBundleProvider'
```
