# Forge Policy Intent Examples For Manual KLIQ Tests

This is the Forge-side copy/paste path for manual KLIQ tests. It shows:

- how to write a simple `AccessPolicy` intent;
- how Forge builds a `RuntimePolicyPack` for standalone KLIQ;
- how Forge serves the same intent as a signed `RuntimeBundle` for managed
  mode;
- which variants are useful for simple and more complex policy tests.

The KLIQ-side guide is in `kernloom/_docs/testing/manual-test-guide.md`.

## Mental Model

| Artifact | Created By | Used By | Purpose |
|---|---|---|---|
| `AccessPolicy` | Operator / Git-PAP | Forge | Business policy intent |
| `EnforcementPlan` | `forge compile` | Operator / report | Shows coverage, downgrades, delegation, gaps |
| `RuntimePolicyPack` | `forge export-runtime-policy` | Standalone KLIQ with `--policy-file` | Local RuntimePDP rules |
| `RuntimeBundle` | `forge build-runtime-bundle` or `forge serve` | KLIQ managed mode | Signed bundle with registry snapshot and pack |

Important: `forge compile --output yaml` creates an `EnforcementPlan`, not a
file for `kliq --policy-file`. For standalone KLIQ, always use
`forge export-runtime-policy`.

## Setup

```bash
mkdir -p /tmp/kernloom-forge-manual/policies /tmp/kernloom-forge-manual/out

cd /home/adrian/prj/ebpf-security/kernloom-forge
mkdir -p bin
go build -o bin/forge ./cmd/forge
```

Optionally build KLIQ:

```bash
cd /home/adrian/prj/ebpf-security/kernloom
mkdir -p bin
go build -o bin/kliq ./iq/cmd/kliq
```

## 1. Base Intent: Risk And Device Posture

This intent is small enough for the first test, but complete enough to create
two compensating runtime rules.

```bash
cd /home/adrian/prj/ebpf-security/kernloom-forge

cat > /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml <<'EOF'
apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: manual-edge-access
  owner: lab-operator
spec:
  subject:
    type: role
    ref: edge-clients
  action: access
  resource:
    type: service
    ref: public-edge
  conditions:
    - id: require-low-risk
      type: risk_level
      signal: subject.risk.level
      operator: eq
      value: low
    - id: require-healthy-device
      type: device_posture
      signal: device.posture.status
      operator: eq
      value: healthy
  effect: allow
EOF
```

Registry terms used here:

| Field | Registry |
|---|---|
| `subject.type: role` | Forge intent selector; later mapped to canonical subjects |
| `resource.type: service` | Entity/taxonomy vocabulary |
| `subject.risk.level` | Context Key + Risk Taxonomy |
| `device.posture.status` | Context Key |
| `low`, `healthy`, `unknown` | Allowed canonical values |

## 2. Check The Intent With Forge

```bash
./bin/forge validate \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml

./bin/forge compile \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output summary

./bin/forge report \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output /tmp/kernloom-forge-manual/out/manual-edge-report.yaml
```

Expected:

- `manual-edge-access -> klshield-local` appears in the summary.
- `risk_level` and `device_posture` are mapped as `compensating_control` for
  `klshield-local`.
- The report has no unexpected `unsupported` requirements.

Debug:

```bash
grep -E 'target:|deployable:|status:|support:|fidelity:|downgrade|compensating' \
  /tmp/kernloom-forge-manual/out/manual-edge-report.yaml
```

## 3. Build A RuntimePolicyPack For Standalone KLIQ

```bash
./bin/forge export-runtime-policy \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --ttl 30s \
  --output /tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml
```

Check the pack:

```bash
grep -E 'kind: RuntimePolicyPack|capabilities_required:|when:|capability:|level:' \
  /tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml
```

Expected:

- `kind: RuntimePolicyPack`
- `capability: enforce.access.deny`
- a rule for `risk.level in ['high', 'critical']`
- a rule for `device.posture.status in ['degraded', 'unhealthy', 'unknown']`

Why `deny`? In the example target `klshield-local`, `risk_level` and
`device_posture` are mapped as compensating restrictions. Forge therefore
creates local RuntimePDP rules that treat bad or unknown evidence as
restrictive.

## 4. Load The Pack In Standalone KLIQ

No-root smoke test without an adapter:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file=/tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-forge-manual/out/state-standalone.json \
  --db=/tmp/kernloom-forge-manual/out/kliq-standalone.db \
  --interval=2s
```

Expected:

- `Policy loaded: ... kind=RuntimePolicyPack`
- `[runtime-pdp] pack loaded: 2 rules`
- `RuntimePDP mode: SHADOW`
- no parse or compile errors.

Optional KLShield run, still without real PEP writes:

```bash
sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-forge-manual/out/manual-edge-runtime-pack.yaml \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-forge-manual/out/state-klshield.json \
  --db=/tmp/kernloom-forge-manual/out/kliq-klshield.db \
  --interval=1s
```

Use `--dry-run=false` only after a successful dry-run and a clear operator
decision.

## 5. Managed Mode With A Signed RuntimeBundle

Managed mode tests the signature, registry snapshot, bundle activation, and
RuntimePolicyPack handoff.

Create keys:

```bash
cd /home/adrian/prj/ebpf-security/kernloom-forge

./bin/forge keygen \
  --private /tmp/kernloom-forge-manual/out/forge-runtime.key \
  --public /tmp/kernloom-forge-manual/out/forge-runtime.pub
```

Build one bundle as a file:

```bash
./bin/forge build-runtime-bundle \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --node-id node-manual-1 \
  --generation 1 \
  --runtime-pdp-mode shadow \
  --failover fail_static \
  --signing-key /tmp/kernloom-forge-manual/out/forge-runtime.key \
  --output /tmp/kernloom-forge-manual/out/manual-edge-runtime-bundle.yaml
```

Check the bundle:

```bash
grep -E 'kind: RuntimeBundle|registry_snapshot:|runtime_policy_pack:|signature:' \
  /tmp/kernloom-forge-manual/out/manual-edge-runtime-bundle.yaml
```

Pre-register the KLIQ node and copy the printed `enroll_token`:

```bash
./bin/forge enroll-token create \
  --store /tmp/kernloom-forge-manual/out/enroll-tokens.yaml \
  --node-id node-manual-1 \
  --ttl 24h
```

Start Forge as the control plane:

```bash
./bin/forge serve \
  --addr :18443 \
  --policy /tmp/kernloom-forge-manual/policies/manual-edge-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target klshield-local \
  --signing-key /tmp/kernloom-forge-manual/out/forge-runtime.key \
  --enroll-token-store /tmp/kernloom-forge-manual/out/enroll-tokens.yaml \
  --generation 1 \
  --runtime-pdp-mode shadow \
  --failover fail_static
```

Health check:

```bash
curl -fsS http://localhost:18443/healthz
```

Start KLIQ in managed mode. Replace `PASTE_ENROLL_TOKEN_HERE` with the token
printed by `forge enroll-token create`:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 30s ./bin/kliq run \
  --adapter=none \
  --graph-node-id=node-manual-1 \
  --mode=managed \
  --forge-url=http://localhost:18443 \
  --forge-enroll-token=PASTE_ENROLL_TOKEN_HERE \
  --policy-verify-key=/tmp/kernloom-forge-manual/out/forge-runtime.pub \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-forge-manual/out/state-managed.json \
  --db=/tmp/kernloom-forge-manual/out/kliq-managed.db \
  --interval=2s
```

Expected:

- Forge logs enrollment, heartbeat, and bundle requests.
- KLIQ logs that it applied a RuntimeBundle.
- KLIQ writes `managed/current-bundle.yaml` next to the state file.
- KLIQ rejects bundles without a valid signature or without a registry snapshot.

Note: the Forge API server is still an MVP. Enrollment tokens and session tokens
are stored in memory while the server runs, but the enrollment token store keeps
used/unused token state on disk.

## Variants From Simple To Complex

| Example | Policy | Target | Expected Result |
|---|---|---|---|
| Risk gate only | One condition: `subject.risk.level == low` | `klshield-local` | Small pack with one deny rule for high/critical risk |
| Risk + device posture | Base example above | `klshield-local` | Two compensating runtime rules |
| Investor apps overlay | `examples/policies/investor-apps-access.yaml` | `openziti-production` | MFA delegated, device posture partial, risk as compensating runtime control |
| Network tuple governance | Conditions on `network.protocol` and `network.port` | `klshield-local` or `netfilter` | Good report/mapping check; may end without runtime rules |
| Strict admin Config PDP | MFA + risk + device posture, `allowDelegation: false`, `allowSemanticDowngrade: false` | `openziti-production` | Config PDP should deny when delegation or downgrade would be needed |

Investor example:

```bash
cd /home/adrian/prj/ebpf-security/kernloom-forge

./bin/forge report \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --output /tmp/kernloom-forge-manual/out/investor-report.yaml

./bin/forge export-runtime-policy \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target openziti-production \
  --ttl 30s \
  --output /tmp/kernloom-forge-manual/out/investor-openziti-pack.yaml
```

Strict Config PDP example:

```bash
./bin/forge config-pdp validate \
  --policy examples/policies/investor-apps-access.yaml \
  --adapters examples/adapters \
  --profiles examples/profiles \
  --target openziti-production \
  --output /tmp/kernloom-forge-manual/out/investor-config-pdp.yaml
```

## Quick Debug

If `export-runtime-policy` creates no rules:

- Check the target profile. Only `compensating_control` creates local runtime
  rules.
- Check the adapter mapping: `examples/adapters/<adapter>/mappings.yaml`.
- Check the runtime action. Grant actions are config/proposal-only.
- For first standalone tests, use `klshield-local` with `risk_level` or
  `device_posture`.

Useful grep commands:

```bash
grep -E 'unsupported|partial|downgrade|compensating|deployable' \
  /tmp/kernloom-forge-manual/out/*.yaml

grep -E 'kind: RuntimePolicyPack|when:|capability:|level:' \
  /tmp/kernloom-forge-manual/out/*pack.yaml

grep -E 'kind: RuntimeBundle|registry_snapshot:|signature:' \
  /tmp/kernloom-forge-manual/out/*bundle.yaml
```
