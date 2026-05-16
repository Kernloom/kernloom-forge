# Kernloom Forge

**Kernloom Forge** is the policy compiler and control plane for [Kernloom](https://kernloom.com).
It owns the standardised Kernloom language — intents, capabilities, signals, granularities — and
compiles abstract policies into node-specific enforcement plans for KLIQ nodes.

Forge does not enforce anything itself. It compiles, signs, and distributes.
KLIQ enforces locally via its plugin adapters (KLShield, NGINX, OpenZiti, …).

```
Policy Author  →  forge compile  →  CompilerDecisionReport
                                         ↓
                                  CompiledPolicyPack (signed)
                                         ↓
                               KLIQ pulls & enforces locally
```

---

## What Forge does today

| Feature | Status |
|---|---|
| Core registry loading and cross-validation | ✅ |
| Node definition validation (v1alpha2) | ✅ |
| Policy validation with CEL bindings and baseline requirements | ✅ |
| Policy compiler — capability matching, scoring, decision report | ✅ |
| `forge compile` CLI | ✅ |
| Pack signing, managed server, enrollment | Phase 4 |

---

## Quick start

```bash
# Run all tests
make test

# Validate the core registry, all node definitions, and all example policies
make validate

# Compile an example policy and see which nodes are selected
make compile-example

# Build the forge binary
make build
./bin/forge --help
```

---

## CLI

```bash
# Validate the core registry
forge registry validate registries/core

# Validate a node definition against the registry
forge adapter validate examples/nodes/l3l4-xdp-filter.yaml

# Validate a policy
forge policy validate examples/policies/mitigate-connection-spike.yaml

# Compile a policy against registered nodes
forge compile examples/policies/mitigate-connection-spike.yaml \
  --registry registries/core \
  --nodes    examples/nodes
```

The compiler outputs a `CompilerDecisionReport`:

```yaml
kind: CompilerDecisionReport
apiVersion: forge.kernloom.io/v1alpha2
status: success
policy_id: mitigate-src-connection-spike
selected_plan:
  analyzers:
    - node_id: local-risk-engine-01
      capabilities: [analyze.baseline.compare]
      score: 44
  enforcers:
    - node_id: l3l4-xdp-filter-edge-01
      capabilities: [observe.network.connection, enforce.traffic.rate_limit]
      score: 84
fallbacks:
  - node_id: tcp-proxy-edge-01
    capabilities: [observe.network.connection]
    score: 56
```

---

## Repository layout

```
registries/core/
  capabilities.yaml        Generic capability vocabulary
  component_roles.yaml     Functional roles: pep, sensor, analyzer, pdp, pip, controller, sink
  component_profiles.yaml  Technical profiles: network.l3_l4_filter, network.transport_proxy, …
  baseline_statistics.yaml Standardised analyzer output fields (upper_bound, confidence, phase, …)
  selection_traits.yaml    Compiler scoring dimensions (enforcement_position, blast_radius, …)
  signals.yaml             Standardised signals (network.metric.*, baseline.*, anomaly.*, risk.*)
  granularities.yaml       Observation/enforcement dimensions (src_ip, tuple_5, listener_id, …)
  intents.yaml             Abstract policy goals (protection.abuse.mitigate, relation.freeze, …)
  compiler_rules.yaml      Intent → capability mappings

examples/
  nodes/                   Example node definitions (l3l4-xdp-filter, tcp-proxy, local-risk-engine)
  policies/                Example policies including baseline-driven mitigation

internal/
  registry/                Registry loader and model (ComponentRole, ComponentProfile, …)
  validator/               Node definition and policy validators
  compiler/                Policy compiler: CompilePolicy, scoreNode, CompileResult

cmd/forge/                 CLI entry point
```

---

## Core model

```
ComponentRole    = what functional role  (pep / sensor / analyzer / pdp / pip / controller / sink)
ComponentProfile = how it operates       (network.l3_l4_filter / network.transport_proxy / …)
NodeDefinition   = concrete declaration  (roles + profiles + capabilities + selection_traits)

Intent           = abstract policy goal  (protection.abuse.mitigate)
Capability       = technical means       (enforce.traffic.rate_limit)
Signal           = standardised data     (network.metric.connections_per_second)
Granularity      = action precision      (src_ip / tuple_5 / listener_id)
```

Compiler scoring weights (from `selection_traits`):

| Trait | Weight | Better direction |
|---|---|---|
| `enforcement_position` | 30 | early > mid > late > control_plane |
| `runtime_cost` | 20 | very_low > low > medium > high |
| `source_attribution` | 20 | strong > conditional > weak |
| `blast_radius` | 10 | packet < flow < listener < node < … |
| `convergence_speed` | 10 | immediate > fast > eventual |

---

## Policy language

Policies use [CEL](https://cel.dev) for `when:` conditions. Bindings connect CEL variables
to live signals and baseline statistics produced by analyzer nodes:

```yaml
kind: RuntimePolicy
apiVersion: forge.kernloom.io/v1alpha2

metadata:
  id: mitigate-src-connection-spike

intent: protection.abuse.mitigate

requirements:
  required_capabilities:
    - observe.network.connection
    - analyze.baseline.compare
    - enforce.traffic.rate_limit
  min_granularity: [src_ip]
  degradation:
    allow: false

when:
  language: cel
  bindings:
    current_cps:
      from: signal
      id: network.metric.connections_per_second
      scope: src_ip
    src_upper:
      from: baseline
      signal: network.metric.connections_per_second
      scope: src_ip
      statistic: upper_bound
    src_phase:
      from: baseline
      signal: network.metric.connections_per_second
      scope: src_ip
      statistic: phase
  expression: >
    vars.src_phase == "stable" &&
    vars.current_cps > vars.src_upper * 1.5

then:
  - type: capability_action
    capability: enforce.traffic.rate_limit
    target:
      granularity: src_ip
      value_from: signals.network.entity.src_ip
    parameters:
      ttl: 10m
```

---

## License

MPL-2.0 — see [LICENSE](LICENSE) and [LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt).
