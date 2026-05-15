# Kernloom Forge

[![CI](https://github.com/Kernloom/kernloom-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Kernloom/kernloom-forge/actions/workflows/ci.yml)

**Kernloom Forge** is the policy compiler and control plane for [Kernloom](https://github.com/Kernloom/kernloom). It owns the standardised Kernloom language (intents, capabilities, signals) and compiles abstract policies into node-specific enforcement configurations for KLIQ.

## What Forge does

- **Registry validation** — loads and cross-validates the core Kernloom language registries
- **Adapter manifest validation** — verifies adapter manifests against the registry
- **Policy validation** — verifies policies reference only known intents, capabilities and signals
- **Policy compilation** — translates abstract intents into concrete capability actions per node *(Phase 2)*
- **Runtime config builder** — generates signed KLIQ runtime configs *(Phase 3)*
- **Managed control plane** — node enrollment, heartbeats, drift detection *(Phase 4)*

## Install

```bash
go install github.com/kernloom/kernloom-forge/cmd/forge@latest
```

## Usage

```bash
# Validate core registry
forge registry validate ./registries/core

# Validate an adapter manifest
forge adapter validate examples/adapters/klshield.manifest.yaml

# Validate a policy file
forge policy validate examples/policies/dos-prevention.yaml
```

## Repository structure

```
registries/core/    Core Kernloom language (intents, capabilities, signals, ...)
examples/           Example adapter manifests and policies
internal/registry/  Registry loader and model
internal/validator/ Adapter and policy validators
internal/compiler/  Policy compiler (Phase 2)
cmd/forge/          CLI entry point
```

## Policy language

Policies use [CEL](https://cel.dev) for `when:` conditions and reference standardised Kernloom IDs:

```yaml
kind: RuntimePolicy
metadata:
  id: block-critical-source
when:
  language: cel
  expression: signals.anomaly.state.severity == "critical"
then:
  - type: capability_action
    capability: enforce.network.deny
    target:
      granularity: src_ip
      value_from: signals.network.entity.src_ip
    ttl: 30m
```

## License

MPL-2.0 — see [LICENSE](LICENSE).
