```
Human
  |
  |  Natural Intent
  |  "protect production database;
  |   require low risk;
  |   when abuse -> rate limit, then block"
  v

Forge
  |
  |  1. convertiert Natural Intent
  |     -> PolicyIntent Manifest
  |     -> AccessPolicy / RequirementPolicy / DetectionPolicy
  |     -> ResponsePolicy / GuardrailPolicy / CapabilityRequirement
  |
  |  2. vergleicht mit enrollten Nodes
  |     + Labels + Capabilities
  |
  +-----------------------------+-----------------------------+
  |                             |                             |
  v                             v                             v

Node A: KLIQ                  Node B: KLIQ                  Missing Target
capabilities:                 capabilities:                 capability:
- klshield                    - idp-config                  - waf.edge.block
- enforce.traffic.drop        - group membership write       not enrolled
- rate_limit
labels:                       labels:
- role=edge-gateway           - role=idp-admin
- service=database            - service=identity
  |                             |                             |
  | gets only:                  | gets only:                  | Forge report:
  | klshield runtime pack       | idp/config policy pack      | GAP
  |                             |                             | no deployable pack
  v                             v                             v

Local Runtime PDP             Local Config PDP              Warning / non-deployable
inside KLIQ                   inside KLIQ                   plan
  |
  | evaluates only local facts/signals:
  | - local flow
  | - local risk
  | - previous local action
  | - allowed blast radius
  v

PEP / Adapter
klshield / netfilter / cgroup / etc.
  |
  | sees only concrete enforcement action:
  | - rate_limit source for 15m
  | - drop traffic
  | - deny cgroup/process access
  v

Target System
host / workload / network path
```
