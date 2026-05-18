// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler and registry validator.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/assessment"
	"github.com/kernloom/kernloom-forge/internal/compiler"
	"github.com/kernloom/kernloom-forge/internal/forgeapi"
	"github.com/kernloom/kernloom-forge/internal/forgedb"
	"github.com/kernloom/kernloom-forge/internal/packs"
	"github.com/kernloom/kernloom-forge/internal/registry"
	"github.com/kernloom/kernloom-forge/internal/signing"
	"github.com/kernloom/kernloom-forge/internal/validator"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// resolveRegistryDir resolves the registry directory with three fallbacks:
//  1. FORGE_REGISTRY_DIR env var (highest priority)
//  2. The path as given (works when running from repo root)
//  3. <binary-dir>/registries/core (works for installed binaries)
func resolveRegistryDir(flagVal string) string {
	if env := os.Getenv("FORGE_REGISTRY_DIR"); env != "" {
		return env
	}
	if _, err := os.Stat(flagVal); err == nil {
		return flagVal
	}
	// Try relative to the binary.
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "registries", "core")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return flagVal // return as-is; LoadDir will produce a clear error
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "forge",
		Short: "Kernloom Forge — policy compiler and registry validator",
	}
	root.AddCommand(registryCmd())
	root.AddCommand(adapterCmd())
	root.AddCommand(policyCmd())
	root.AddCommand(compileCmd())
	root.AddCommand(packCmd())
	root.AddCommand(keygenCmd())
	root.AddCommand(serveCmd())
	root.AddCommand(tokenCmd())
	root.AddCommand(nodesCmd())
	root.AddCommand(assessCmd())
	return root
}

// ── forge registry ────────────────────────────────────────────────────────────

func registryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Registry operations",
	}
	cmd.AddCommand(registryValidateCmd())
	cmd.AddCommand(registryListCmd())
	return cmd
}

func registryListCmd() *cobra.Command {
	var registryDir string
	validNames := []string{
		"capabilities", "signals", "intents", "granularities", "scopes",
		"component_roles", "component_profiles", "baseline_statistics",
		"selection_traits", "compiler_rules",
		"effect_types", "policy_contexts",
		"action_constraints", "trust_assurance_levels",
		"decision_modes", "failover_behaviors",
	}
	cmd := &cobra.Command{
		Use:   "list [registry-name]",
		Short: "List all registries, or entries of a specific registry",
		Long: `Without arguments: show all available registries with their entry counts.
With a registry name: print all entries in that registry.

Example:
  forge registry list
  forge registry list capabilities
  forge registry list action_constraints`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}

			// No argument → show overview of all registries.
			if len(args) == 0 {
				rows := []struct{ name, count, desc string }{
					{"capabilities", fmt.Sprintf("%d", len(reg.Capabilities)), "What adapters can do"},
					{"signals", fmt.Sprintf("%d", len(reg.Signals)), "Measurable data points"},
					{"intents", fmt.Sprintf("%d", len(reg.Intents)), "Abstract policy goals"},
					{"granularities", fmt.Sprintf("%d", len(reg.Granularities)), "Precision levels for enforcement"},
					{"scopes", fmt.Sprintf("%d", len(reg.Scopes)), "Aggregation contexts for baselines"},
					{"component_roles", fmt.Sprintf("%d", len(reg.ComponentRoles)), "Functional roles of components"},
					{"component_profiles", fmt.Sprintf("%d", len(reg.ComponentProfiles)), "Technical component templates"},
					{"baseline_statistics", fmt.Sprintf("%d", len(reg.BaselineStatistics)), "Statistic dimensions for baselines"},
					{"selection_traits", fmt.Sprintf("%d", len(reg.SelectionTraits)), "Compiler scoring dimensions"},
					{"compiler_rules", fmt.Sprintf("%d", len(reg.CompilerRules)), "Intent → capability mappings"},
					{"effect_types", fmt.Sprintf("%d", len(reg.EffectTypes)), "Policy effect types"},
					{"policy_contexts", fmt.Sprintf("%d", len(reg.PolicyContexts)), "Evaluation contexts"},
					{"action_constraints", fmt.Sprintf("%d", len(reg.ActionConstraints)), "Constraint keys for effects[].constraints"},
					{"trust_assurance_levels", fmt.Sprintf("%d", len(reg.TrustAssuranceLevels)), "Ordered trust scale (unknown → attested)"},
					{"decision_modes", fmt.Sprintf("%d", len(reg.DecisionModes)), "How local PDP interacts with Forge"},
					{"failover_behaviors", fmt.Sprintf("%d", len(reg.FailoverBehaviors)), "Behavior when Forge is unreachable"},
				}
				fmt.Printf("%-25s  %5s  %s\n", "REGISTRY", "COUNT", "DESCRIPTION")
				fmt.Printf("%-25s  %5s  %s\n", strings.Repeat("-", 25), "-----", strings.Repeat("-", 40))
				for _, r := range rows {
					fmt.Printf("%-25s  %5s  %s\n", r.name, r.count, r.desc)
				}
				fmt.Printf("\nUse: forge registry list <name> to see entries.\n")
				return nil
			}

			name := args[0]
			switch name {
			case "capabilities":
				for id, c := range reg.Capabilities {
					fmt.Printf("%-50s  %s / %s  risk:%s\n", id, c.Category, c.Domain, c.RiskClass)
				}
			case "signals":
				for id, s := range reg.Signals {
					fmt.Printf("%-50s  %s/%s  unit:%s\n", id, s.Domain, s.Type, s.Unit)
				}
			case "intents":
				for id, v := range reg.Intents {
					fmt.Printf("%-50s  %s\n", id, v.Description)
				}
			case "granularities":
				for id, v := range reg.Granularities {
					fmt.Printf("%-30s  group:%s\n", id, v.Group)
				}
			case "scopes":
				for id := range reg.Scopes {
					fmt.Println(id)
				}
			case "component_roles":
				for id, v := range reg.ComponentRoles {
					fmt.Printf("%-20s  %s\n", id, v.Description)
				}
			case "component_profiles":
				for id, v := range reg.ComponentProfiles {
					fmt.Printf("%-30s  %s\n", id, v.Description)
				}
			case "baseline_statistics":
				for id, v := range reg.BaselineStatistics {
					fmt.Printf("%-20s  %s  type:%s\n", id, v.Description, v.ValueType)
				}
			case "selection_traits":
				for id, v := range reg.SelectionTraits {
					fmt.Printf("%-30s  values:%v\n", id, v.AllowedValues)
				}
			case "compiler_rules":
				for id, v := range reg.CompilerRules {
					fmt.Printf("%-30s  intent:%s  targets:%d\n", id, v.Intent, len(v.Targets))
				}
			case "effect_types":
				for id, v := range reg.EffectTypes {
					fmt.Printf("%-20s  contexts:%v\n", id, v.AllowedContexts)
				}
			case "policy_contexts":
				for id, v := range reg.PolicyContexts {
					fmt.Printf("%-15s  effects:%v\n", id, v.AllowedEffects)
				}
			case "action_constraints":
				for id, v := range reg.ActionConstraints {
					fmt.Printf("%-35s  type:%-12s  applies_to:%v\n", id, v.ValueType, v.AppliesTo)
				}
			case "trust_assurance_levels":
				// Print ordered by level.
				levels := make([]*registry.TrustAssuranceLevel, 0, len(reg.TrustAssuranceLevels))
				for _, v := range reg.TrustAssuranceLevels {
					levels = append(levels, v)
				}
				// Simple sort by level int.
				for i := 0; i < len(levels)-1; i++ {
					for j := i + 1; j < len(levels); j++ {
						if levels[i].Level > levels[j].Level {
							levels[i], levels[j] = levels[j], levels[i]
						}
					}
				}
				for _, v := range levels {
					def := ""
					if v.Default {
						def = "  [default]"
					}
					fmt.Printf("  %d  %-20s%s\n", v.Level, v.ID, def)
				}
			case "decision_modes":
				for id, v := range reg.DecisionModes {
					def := ""
					if v.Default {
						def = "  [default]"
					}
					fmt.Printf("%-25s%s\n", id, def)
				}
			case "failover_behaviors":
				for id, v := range reg.FailoverBehaviors {
					def := ""
					if v.Default {
						def = "  [default]"
					}
					fmt.Printf("%-25s  risk:%-6s%s\n", id, v.Risk, def)
				}
			default:
				return fmt.Errorf("unknown registry %q\n\nAvailable: %s", name, strings.Join(validNames, ", "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	return cmd
}

func registryValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <dir>",
		Short: "Validate all core registry files in a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("OK  registry loaded: %d intents  %d capabilities  %d signals  %d granularities  %d component_roles  %d compiler_rules\n",
				len(reg.Intents), len(reg.Capabilities), len(reg.Signals),
				len(reg.Granularities), len(reg.ComponentRoles), len(reg.CompilerRules))
			return nil
		},
	}
}

// ── forge adapter ─────────────────────────────────────────────────────────────

func adapterCmd() *cobra.Command {
	var registryDir string
	cmd := &cobra.Command{
		Use:   "adapter",
		Short: "Node definition (adapter) operations",
	}
	validateCmd := &cobra.Command{
		Use:   "validate <node-definition.yaml>",
		Short: "Validate a node definition against the core registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			if err := validator.ValidateAdapterFile(args[0], reg); err != nil {
				return err
			}
			fmt.Printf("OK  node definition %s is valid\n", args[0])
			return nil
		},
	}
	validateCmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.AddCommand(validateCmd)
	return cmd
}

// ── forge policy ──────────────────────────────────────────────────────────────

func policyCmd() *cobra.Command {
	var registryDir string
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy operations",
	}
	validateCmd := &cobra.Command{
		Use:   "validate <policy.yaml>",
		Short: "Validate a policy file against the core registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			if err := validator.ValidatePolicyFile(args[0], reg); err != nil {
				return err
			}
			fmt.Printf("OK  policy %s is valid\n", args[0])
			return nil
		},
	}
	validateCmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.AddCommand(validateCmd)
	cmd.AddCommand(policyNormalizeCmd())
	cmd.AddCommand(policyExplainCmd())
	cmd.AddCommand(policyCompileCmd())
	return cmd
}

func policyNormalizeCmd() *cobra.Command {
	var registryDir string
	cmd := &cobra.Command{
		Use:   "normalize <policy.yaml>",
		Short: "Normalize a policy to canonical kind:Policy format and print it",
		Long: `Convert a legacy RuntimePolicy or AssessmentPolicy to the canonical Policy
format with spec.context, spec.inputs.bindings and spec.rules[].effects[].

Useful for understanding how Forge interprets a policy before compilation.

Example:
  forge policy normalize examples/policies/dos-prevention.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := validator.ParsePolicyFile(args[0])
			if err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			if err := validator.ValidatePolicy(&p, reg); err != nil {
				return fmt.Errorf("invalid policy: %w", err)
			}
			out, err := validator.MarshalNormalized(&p)
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}
			fmt.Print(string(out))
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	return cmd
}

// ── forge policy explain ──────────────────────────────────────────────────────

func policyExplainCmd() *cobra.Command {
	var registryDir string
	var nodesDir string
	cmd := &cobra.Command{
		Use:   "explain <policy.yaml>",
		Short: "Explain a policy: capabilities, bindings, rules and potential node matches",
		Long: `Parse, normalize and explain a policy in human-readable form.
Shows required capabilities, CEL bindings, rules with expressions,
effect types, constraints, and which registered nodes could satisfy it.

Example:
  forge policy explain examples/policies/dos-prevention.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := validator.ParsePolicyFile(args[0])
			if err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			if err := validator.ValidatePolicy(&p, reg); err != nil {
				return fmt.Errorf("invalid policy: %w", err)
			}
			// Normalization already happened in ValidatePolicy.

			fmt.Printf("Policy:   %s\n", p.Metadata.ID)
			if p.Metadata.Name != "" {
				fmt.Printf("Name:     %s\n", p.Metadata.Name)
			}
			fmt.Printf("Context:  %s\n", p.Spec.Context)
			if p.Spec.Intent != "" {
				fmt.Printf("Intent:   %s\n", p.Spec.Intent)
			}
			fmt.Println()

			// Requirements.
			caps := p.Spec.Requirements.Capabilities
			if len(caps) == 0 {
				caps = p.Spec.Requirements.RequiredCapabilities
			}
			if len(caps) > 0 {
				fmt.Println("Requirements:")
				for _, capID := range caps {
					c := reg.Capabilities[capID]
					if c != nil {
						fmt.Printf("  %-45s  (%s, %s)\n", capID, c.Category, c.RiskClass)
					} else {
						fmt.Printf("  %s\n", capID)
					}
				}
				fmt.Println()
			}

			// Shared bindings.
			if len(p.Spec.Inputs.Bindings) > 0 {
				fmt.Println("Bindings (shared across all rules):")
				for name, b := range p.Spec.Inputs.Bindings {
					switch b.From {
					case "signal":
						fmt.Printf("  %-20s ← signal   %s @ %s\n", name, b.ID, b.Scope)
					case "baseline":
						fmt.Printf("  %-20s ← baseline %s @ %s [%s]\n", name, b.Signal, b.Scope, b.Statistic)
					case "asset":
						fmt.Printf("  %-20s ← asset path: %s\n", name, b.Path)
					}
				}
				fmt.Println()
			}

			// Rules.
			fmt.Printf("Rules (%d):\n", len(p.Spec.Rules))
			for i, rule := range p.Spec.Rules {
				fmt.Printf("  [%d] %s\n", i, rule.ID)
				if rule.When.Expression != "" {
					expr := strings.TrimSpace(rule.When.Expression)
					if len(expr) > 80 {
						expr = expr[:77] + "..."
					}
					fmt.Printf("      when: %s\n", expr)
				}
				if len(rule.When.Bindings) > 0 {
					fmt.Printf("      bindings (local overrides): %d\n", len(rule.When.Bindings))
				}
				for j, eff := range rule.Effects {
					action := eff.Action
					if action == "" {
						action = eff.Capability
					}
					if action == "" && eff.Intent != "" {
						action = "intent:" + eff.Intent
					}
					ttl := ""
					if t, ok := eff.Constraints["ttl"].(string); ok {
						ttl = "  ttl:" + t
					}
					fmt.Printf("      effect[%d]: %-12s %s%s\n", j, eff.Type, action, ttl)
					if eff.Message != "" {
						fmt.Printf("               message: %s\n", eff.Message)
					}
				}
			}

			// Node matching (optional).
			if nodesDir != "" {
				nodes, err := validator.LoadNodeDefinitionsFromDir(nodesDir, reg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARN  could not load nodes from %s: %v\n", nodesDir, err)
				} else {
					fmt.Println()
					fmt.Println("Node compatibility:")
					for _, node := range nodes {
						canSatisfy := true
						for _, capID := range caps {
							found := false
							for _, ac := range node.Capabilities {
								if ac.ID == capID {
									found = true
									break
								}
							}
							if !found {
								canSatisfy = false
								break
							}
						}
						if canSatisfy {
							fmt.Printf("  ✓  %s\n", node.Metadata.ID)
						} else {
							fmt.Printf("  ✗  %s  (missing capabilities)\n", node.Metadata.ID)
						}
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.Flags().StringVar(&nodesDir, "nodes", "", "path to node definitions directory (optional, shows node compatibility)")
	return cmd
}

// ── forge policy compile ──────────────────────────────────────────────────────

func policyCompileCmd() *cobra.Command {
	var registryDir string
	var nodesDir string
	var outFile string
	var signingKeyPath string
	var forgeURL string

	cmd := &cobra.Command{
		Use:   "compile <policy.yaml>",
		Short: "Compile a policy into a signed LocalPolicyPack (alias for forge pack)",
		Long: `Validate, compile and sign a single Policy file into a KLIQ-deployable
LocalPolicyPack. This is the canonical entry point for single-policy compilation;
for multi-policy packs use: forge pack build --policy-dir <dir>

Example:
  forge policy compile examples/policies/dos-prevention.yaml \
    --signing-key /etc/kernloom/forge-signing.key \
    --out /tmp/dos-prevention.pack.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			p, err := validator.ParsePolicyFile(args[0])
			if err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			if err := validator.ValidatePolicy(&p, reg); err != nil {
				return fmt.Errorf("invalid policy: %w", err)
			}

			nodes, err := validator.LoadNodeDefinitionsFromDir(nodesDir, reg)
			if err != nil {
				return fmt.Errorf("load nodes: %w", err)
			}

			compileResult, err := compiler.CompilePolicy(compiler.CompileRequest{
				Policy: p, Nodes: nodes,
			}, reg)
			if err != nil {
				return fmt.Errorf("compile: %w", err)
			}
			if compileResult.Status != compiler.StatusSuccess {
				return fmt.Errorf("policy cannot be compiled: missing capabilities %v",
					compileResult.Missing.Capabilities)
			}

			renderResult, err := packs.RenderLocalPolicyPack(packs.RenderRequest{
				Policy: p, ForgeURL: forgeURL,
			})
			if err != nil {
				return fmt.Errorf("render: %w", err)
			}
			for _, w := range renderResult.Warnings {
				fmt.Fprintf(os.Stderr, "WARN  %s\n", w)
			}

			out, err := yaml.Marshal(renderResult.Pack)
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}
			if signingKeyPath != "" {
				privKey, kerr := signing.LoadPrivateKey(signingKeyPath)
				if kerr != nil {
					return fmt.Errorf("load signing key: %w", kerr)
				}
				out, err = signing.SignPackYAML(out, privKey)
				if err != nil {
					return fmt.Errorf("sign: %w", err)
				}
				fmt.Fprintf(os.Stderr, "OK  pack signed with %s\n", signingKeyPath)
			}
			if outFile != "" && outFile != "-" {
				if err := os.WriteFile(outFile, out, 0o644); err != nil {
					return fmt.Errorf("write %s: %w", outFile, err)
				}
				fmt.Fprintf(os.Stderr, "OK  pack written to %s\n", outFile)
			} else {
				fmt.Print(string(out))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.Flags().StringVar(&nodesDir, "nodes", "examples/nodes", "path to node definitions directory")
	cmd.Flags().StringVarP(&outFile, "out", "o", "-", "output file (- for stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "path to Ed25519 private key for signing")
	cmd.Flags().StringVar(&forgeURL, "forge-url", "", "Forge endpoint to include in pack exports")
	return cmd
}

// ── forge pack ────────────────────────────────────────────────────────────────

func packCmd() *cobra.Command {
	var registryDir string
	var nodesDir string
	var forgeURL string
	var outFile string
	var signingKeyPath string

	cmd := &cobra.Command{
		Use:   "pack <policy.yaml>",
		Short: "Render a compiled policy into a KLIQ-deployable LocalPolicyPack",
		Long: `Compile a policy and render the result as a LocalPolicyPack YAML file
that KLIQ can load via --policy-file.

The pack uses Forge vocabulary in capabilities_required and then.capability.
KLIQ maps these to adapter calls via its internal normalisation table.

Example:
  forge pack examples/policies/mitigate-connection-spike.yaml \
    --registry registries/core \
    --nodes examples/nodes \
    --out examples/packs/mitigate-connection-spike.pack.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}

			policy, err := validator.ParsePolicyFile(args[0])
			if err != nil {
				return fmt.Errorf("parse policy: %w", err)
			}
			if err := validator.ValidatePolicy(&policy, reg); err != nil {
				return fmt.Errorf("invalid policy: %w", err)
			}

			nodes, err := validator.LoadNodeDefinitionsFromDir(nodesDir, reg)
			if err != nil {
				return fmt.Errorf("load nodes: %w", err)
			}

			// Compile first to verify the policy is satisfiable.
			compileResult, err := compiler.CompilePolicy(compiler.CompileRequest{
				Policy: policy, Nodes: nodes,
			}, reg)
			if err != nil {
				return fmt.Errorf("compile: %w", err)
			}
			if compileResult.Status != compiler.StatusSuccess {
				return fmt.Errorf("policy cannot be compiled: missing capabilities %v",
					compileResult.Missing.Capabilities)
			}

			// Render the LocalPolicyPack.
			renderResult, err := packs.RenderLocalPolicyPack(packs.RenderRequest{
				Policy:   policy,
				ForgeURL: forgeURL,
			})
			if err != nil {
				return fmt.Errorf("render pack: %w", err)
			}
			for _, w := range renderResult.Warnings {
				fmt.Fprintf(os.Stderr, "WARN  %s\n", w)
			}

			out, err := yaml.Marshal(renderResult.Pack)
			if err != nil {
				return fmt.Errorf("marshal pack: %w", err)
			}

			// Sign the pack if a signing key is provided.
			if signingKeyPath != "" {
				privKey, kerr := signing.LoadPrivateKey(signingKeyPath)
				if kerr != nil {
					return fmt.Errorf("load signing key: %w", kerr)
				}
				out, err = signing.SignPackYAML(out, privKey)
				if err != nil {
					return fmt.Errorf("sign pack: %w", err)
				}
				fmt.Fprintf(os.Stderr, "OK  pack signed with %s\n", signingKeyPath)
			}

			if outFile != "" && outFile != "-" {
				if err := os.WriteFile(outFile, out, 0o644); err != nil {
					return fmt.Errorf("write %s: %w", outFile, err)
				}
				fmt.Fprintf(os.Stderr, "OK  pack written to %s\n", outFile)
			} else {
				fmt.Print(string(out))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.Flags().StringVar(&nodesDir, "nodes", "examples/nodes", "path to node definitions directory")
	cmd.Flags().StringVar(&forgeURL, "forge-url", "", "Forge endpoint to include in pack exports")
	cmd.Flags().StringVarP(&outFile, "out", "o", "-", "output file (- for stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "path to Ed25519 private key for signing the pack")
	cmd.AddCommand(packRegisterCmd())
	cmd.AddCommand(packBuildCmd())
	return cmd
}

// ── forge pack build ──────────────────────────────────────────────────────────

func packBuildCmd() *cobra.Command {
	var registryDir string
	var policyDir string
	var packName string
	var outFile string
	var signingKeyPath string
	var forgeURL string

	cmd := &cobra.Command{
		Use:   "build [policy.yaml ...]",
		Short: "Build a multi-policy pack from multiple RuntimePolicy files",
		Long: `Compile and sign multiple RuntimePolicy files into a single LocalPolicyPack.

Accepts explicit file arguments, --policy-dir, or both. Policies are evaluated
by KLIQ in the order they appear — list more specific or lower-severity rules first.

Each policy contributes its own rules; capabilities_required and
action_authorization are the union across all policies.

Example — explicit files:
  forge pack build policies/dos-basic.yaml policies/syn-flood.yaml \
    --name db-node-pack \
    --signing-key /etc/kernloom/forge-signing.key \
    --out /tmp/db-node-pack.pack.yaml

Example — directory:
  forge pack build --policy-dir policies/db/ \
    --name db-node-pack \
    --signing-key /etc/kernloom/forge-signing.key \
    --out /tmp/db-node-pack.pack.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Collect policy files: directory first, then explicit args.
			var policyFiles []string
			if policyDir != "" {
				entries, err := os.ReadDir(policyDir)
				if err != nil {
					return fmt.Errorf("read --policy-dir %s: %w", policyDir, err)
				}
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					name := e.Name()
					if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
						policyFiles = append(policyFiles, filepath.Join(policyDir, name))
					}
				}
			}
			policyFiles = append(policyFiles, args...)

			if len(policyFiles) == 0 {
				return fmt.Errorf("no policy files — pass files as arguments or use --policy-dir")
			}
			if packName == "" {
				return fmt.Errorf("--name is required")
			}

			// Load registry.
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}

			// Parse + validate each policy.
			var policies []validator.Policy
			for _, path := range policyFiles {
				p, err := validator.ParsePolicyFile(path)
				if err != nil {
					return fmt.Errorf("parse %s: %w", path, err)
				}
				if err := validator.ValidatePolicy(&p, reg); err != nil {
					return fmt.Errorf("invalid %s: %w", path, err)
				}
				policies = append(policies, p)
				fmt.Fprintf(os.Stderr, "OK  %s (%s)\n", p.Metadata.ID, path)
			}

			// Render multi-policy pack.
			renderResult, err := packs.RenderMultiPolicyPack(packs.MultiRenderRequest{
				Policies: policies,
				PackName: packName,
				ForgeURL: forgeURL,
			})
			if err != nil {
				return fmt.Errorf("render: %w", err)
			}
			for _, w := range renderResult.Warnings {
				fmt.Fprintf(os.Stderr, "WARN  %s\n", w)
			}

			out, err := yaml.Marshal(renderResult.Pack)
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}

			// Sign if key provided.
			if signingKeyPath != "" {
				privKey, kerr := signing.LoadPrivateKey(signingKeyPath)
				if kerr != nil {
					return fmt.Errorf("load signing key: %w", kerr)
				}
				out, err = signing.SignPackYAML(out, privKey)
				if err != nil {
					return fmt.Errorf("sign: %w", err)
				}
				fmt.Fprintf(os.Stderr, "OK  signed — %d policies, %d rules\n",
					len(policies), len(renderResult.Pack.Spec.Rules))
			}

			if outFile != "" && outFile != "-" {
				if err := os.WriteFile(outFile, out, 0o644); err != nil {
					return fmt.Errorf("write %s: %w", outFile, err)
				}
				fmt.Fprintf(os.Stderr, "OK  written to %s\n", outFile)
			} else {
				fmt.Print(string(out))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.Flags().StringVar(&policyDir, "policy-dir", "", "directory of policy YAML files (combined with file args)")
	cmd.Flags().StringVar(&packName, "name", "", "pack name written to metadata.name (required)")
	cmd.Flags().StringVarP(&outFile, "out", "o", "-", "output file (- for stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "path to Ed25519 private key for signing")
	cmd.Flags().StringVar(&forgeURL, "forge-url", "", "Forge endpoint to include in pack exports")
	return cmd
}

// ── forge keygen ──────────────────────────────────────────────────────────────

func keygenCmd() *cobra.Command {
	var outPath string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 signing key pair for pack signing",
		Long: `Generate an Ed25519 key pair for signing LocalPolicyPacks.

Writes two files:
  <out>.key     — private key (keep secret, used by forge pack --signing-key)
  <out>.key.pub — public key  (distribute to KLIQ nodes via --policy-verify-key)

Example:
  forge keygen --out /etc/kernloom/forge-signing
  forge pack policy.yaml --signing-key /etc/kernloom/forge-signing.key
  kliq --policy-verify-key /etc/kernloom/forge-signing.key.pub ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := signing.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generate key pair: %w", err)
			}

			privPath := outPath + ".key"
			pubPath := outPath + ".key.pub"

			if err := signing.SavePrivateKey(privPath, priv); err != nil {
				return fmt.Errorf("save private key: %w", err)
			}
			if err := signing.SavePublicKey(pubPath, pub); err != nil {
				return fmt.Errorf("save public key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "OK  private key → %s (mode 0600)\n", privPath)
			fmt.Fprintf(os.Stderr, "OK  public key  → %s\n", pubPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "forge-signing", "output path prefix (appends .key and .key.pub)")
	return cmd
}

// ── forge compile ─────────────────────────────────────────────────────────────

func compileCmd() *cobra.Command {
	var registryDir string
	var nodesDir string

	cmd := &cobra.Command{
		Use:   "compile <policy.yaml>",
		Short: "Compile a policy against registered node definitions",
		Long: `Compile a policy against a set of registered node definitions and print
a CompilerDecisionReport explaining which nodes were selected, which are
fallbacks, and which required capabilities (if any) could not be satisfied.

Example:
  forge compile examples/policies/mitigate-connection-spike.yaml \
    --registry registries/core \
    --nodes examples/nodes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}

			policy, err := validator.ParsePolicyFile(args[0])
			if err != nil {
				return fmt.Errorf("parse policy: %w", err)
			}
			if err := validator.ValidatePolicy(&policy, reg); err != nil {
				return fmt.Errorf("invalid policy: %w", err)
			}

			nodes, err := validator.LoadNodeDefinitionsFromDir(nodesDir, reg)
			if err != nil {
				return fmt.Errorf("load nodes: %w", err)
			}

			result, err := compiler.CompilePolicy(compiler.CompileRequest{
				Policy: policy,
				Nodes:  nodes,
			}, reg)
			if err != nil {
				return fmt.Errorf("compile: %w", err)
			}

			out, err := yaml.Marshal(result)
			if err != nil {
				return fmt.Errorf("marshal result: %w", err)
			}
			fmt.Print(string(out))

			if result.Status != compiler.StatusSuccess {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.Flags().StringVar(&nodesDir, "nodes", "examples/nodes", "path to node definitions directory")
	return cmd
}

// ── forge serve ───────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	var addr string
	var dbPath string
	var adminKey string
	var tlsCert string
	var tlsKey string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Forge control-plane HTTP/HTTPS server",
		Long: `Start the Forge HTTP control-plane that KLIQ nodes enroll into.

KLIQ endpoints (require per-node session token after enrollment):
  POST /api/v1/nodes/enroll                  — one-time token enrollment
  POST /api/v1/nodes/{id}/heartbeat          — periodic liveness + status
  GET  /api/v1/nodes/{id}/policy-pack        — pull assigned signed pack
  POST /api/v1/nodes/{id}/policy-pack/status — report pack apply result

Admin endpoints (require --admin-key or loopback source):
  GET  /api/v1/nodes                         — list enrolled nodes
  POST /api/v1/nodes/{id}/approve            — approve a pending node
  POST /api/v1/nodes/{id}/revoke             — revoke a node
  POST /api/v1/packs?name=<n>               — register a signed pack
  POST /api/v1/nodes/{id}/assign-pack?pack=  — assign a pack to a node
  GET  /api/v1/tokens                        — list enrollment tokens

Enrollment tokens (create with: forge token create):
  forge token create --node <id> --expires 24h

Example (HTTPS):
  forge serve --addr :8443 --db /var/lib/kernloom/forge.db \
              --tls-cert /etc/kernloom/forge.crt \
              --tls-key  /etc/kernloom/forge.key \
              --admin-key $(cat /etc/kernloom/admin.key)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := log.New(os.Stderr, "[forge-serve] ", log.LstdFlags)

			db, err := forgedb.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()
			logger.Printf("database: %s", dbPath)

			if adminKey == "" {
				logger.Printf("WARNING: --admin-key not set — admin endpoints restricted to loopback")
			}

			srv := forgeapi.New(db, adminKey, logger)

			if tlsCert != "" && tlsKey != "" {
				logger.Printf("listening (TLS) on %s", addr)
				return http.ListenAndServeTLS(addr, tlsCert, tlsKey, srv.Handler())
			}
			logger.Printf("WARNING: TLS disabled — use --tls-cert/--tls-key in production")
			logger.Printf("listening on %s", addr)
			return http.ListenAndServe(addr, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to SQLite database file")
	cmd.Flags().StringVar(&adminKey, "admin-key", "", "admin API key (Authorization: Bearer); empty = loopback-only")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "path to TLS certificate file (enables HTTPS)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "path to TLS private key file (enables HTTPS)")
	return cmd
}

// ── forge assess ─────────────────────────────────────────────────────────────

func assessCmd() *cobra.Command {
	var registryDir string
	var policyDir string
	var policyFiles []string
	var assetType string
	var assetSchema string
	var format string

	cmd := &cobra.Command{
		Use:   "assess <asset.yaml>",
		Short: "Assess a config asset against AssessmentPolicy rules",
		Long: `Evaluate a YAML/JSON config asset (Kubernetes manifest, KliqDeploymentConfig,
Terraform plan, etc.) against a set of AssessmentPolicy files.

Exits 0 when the verdict is "allow" or "warn".
Exits 1 when the verdict is "deny" (at least one error-severity violation).

Example — Kubernetes manifest:
  forge assess k8s/deployment.yaml \
    --policy-dir policies/assessment/ \
    --kind kubernetes_manifest

Example — pipeline gate (fails build on deny):
  forge assess $ASSET --policy-dir policies/assessment/ || exit 1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read asset.
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read asset %s: %w", args[0], err)
			}
			meta := map[string]any{}
			if assetType != "" {
				meta["asset_type"] = assetType
			}
			if assetSchema != "" {
				meta["schema_id"] = assetSchema
			}
			asset, err := assessment.ParseAsset(raw, meta)
			if err != nil {
				return fmt.Errorf("parse asset: %w", err)
			}

			// Collect policy files.
			var files []string
			if policyDir != "" {
				entries, err := os.ReadDir(policyDir)
				if err != nil {
					return fmt.Errorf("read --policy-dir %s: %w", policyDir, err)
				}
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					name := e.Name()
					if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
						files = append(files, filepath.Join(policyDir, name))
					}
				}
			}
			files = append(files, policyFiles...)
			if len(files) == 0 {
				return fmt.Errorf("no policy files — use --policy-dir or --policy")
			}

			// Load registry and parse policies.
			reg, err := registry.LoadDir(resolveRegistryDir(registryDir))
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			var policies []validator.Policy
			for _, path := range files {
				p, err := validator.ParsePolicyFile(path)
				if err != nil {
					return fmt.Errorf("parse %s: %w", path, err)
				}
				// Normalize so spec.context is populated for kind:Policy files.
				p.Normalize()
				isAsset := p.Kind == "AssessmentPolicy" ||
					(p.Kind == "Policy" && p.Spec.Context == "asset")
				if !isAsset {
					continue
				}
				if err := validator.ValidatePolicy(&p, reg); err != nil {
					return fmt.Errorf("invalid %s: %w", path, err)
				}
				policies = append(policies, p)
			}
			if len(policies) == 0 {
				return fmt.Errorf("no AssessmentPolicy or kind:Policy context:asset files found")
			}

			// Run assessment.
			result := assessment.Assess(asset, policies)

			// Output.
			switch format {
			case "json":
				enc := yaml.NewEncoder(os.Stdout)
				_ = enc.Encode(result)
			default:
				icon := map[string]string{"allow": "✓", "warn": "⚠", "deny": "✗"}[result.Verdict]
				fmt.Printf("%s  verdict: %s\n", icon, result.Verdict)
				for _, v := range result.Violations {
					prefix := "  " + v.Severity
					if v.Field != "" {
						fmt.Printf("  [%s] %s: %s\n", v.Severity, v.Field, v.Message)
					} else {
						fmt.Printf("  [%s] %s — %s\n", v.Severity, v.PolicyID, v.Message)
					}
					if v.Remediation != "" {
						fmt.Printf("         → %s\n", v.Remediation)
					}
					_ = prefix
				}
			}

			if result.Verdict == "deny" {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryDir, "registry", "registries/core", "path to core registry directory")
	cmd.Flags().StringVar(&policyDir, "policy-dir", "", "directory of AssessmentPolicy YAML files")
	cmd.Flags().StringArrayVar(&policyFiles, "policy", nil, "explicit AssessmentPolicy file (repeatable)")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "asset type exposed as asset.asset_type in CEL (e.g. kubernetes.manifest, terraform.module)")
	cmd.Flags().StringVar(&assetSchema, "schema-id", "", "schema identifier exposed as asset.schema_id in CEL (e.g. kubernetes.io/apps/v1.Deployment)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

// ── forge token ───────────────────────────────────────────────────────────────

func tokenCmd() *cobra.Command {
	root := &cobra.Command{Use: "token", Short: "Manage enrollment tokens"}
	root.AddCommand(tokenCreateCmd())
	return root
}

func tokenCreateCmd() *cobra.Command {
	var dbPath string
	var nodeID string
	var expires time.Duration

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a one-time enrollment token",
		Long: `Generate a cryptographically random one-time enrollment token.
The token is single-use: KLIQ consumes it on enrollment and it becomes invalid.

Example:
  forge token create --db /var/lib/kernloom/forge.db --node edge-node-01 --expires 24h`,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := forgedb.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()

			b := make([]byte, 24)
			if _, err := rand.Read(b); err != nil {
				return fmt.Errorf("generate token: %w", err)
			}
			token := "kliq-enroll-" + base64.URLEncoding.EncodeToString(b)
			expiresAt := time.Now().Add(expires)

			if err := db.CreateEnrollmentToken(token, nodeID, expiresAt); err != nil {
				return fmt.Errorf("save token: %w", err)
			}

			fmt.Printf("TOKEN=%s\n", token)
			fmt.Fprintf(os.Stderr, "  node:    %s\n", nodeID)
			fmt.Fprintf(os.Stderr, "  expires: %s\n", expiresAt.Format(time.RFC3339))
			fmt.Fprintf(os.Stderr, "\nUse:\n  kliq --forge-enroll-token=%s ...\n", token)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to forge database")
	cmd.Flags().StringVar(&nodeID, "node", "", "bind token to a specific node ID (empty = any node)")
	cmd.Flags().DurationVar(&expires, "expires", 24*time.Hour, "token validity duration")
	return cmd
}

// ── forge nodes ───────────────────────────────────────────────────────────────

func nodesCmd() *cobra.Command {
	root := &cobra.Command{Use: "nodes", Short: "Manage enrolled nodes"}
	root.AddCommand(nodesListCmd())
	root.AddCommand(nodesApproveCmd())
	root.AddCommand(nodesRevokeCmd())
	root.AddCommand(nodesAssignPackCmd())
	return root
}

func nodesListCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled nodes",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := forgedb.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			nodes, err := db.ListNodes()
			if err != nil {
				return err
			}
			fmt.Printf("%-30s %-12s %-10s %s\n", "NODE-ID", "MODE", "STATUS", "ENROLLED")
			for _, n := range nodes {
				fmt.Printf("%-30s %-12s %-10s %s\n",
					n.ID, n.Mode, n.Status, n.EnrolledAt.Format("2006-01-02 15:04"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to forge database")
	return cmd
}

func nodesApproveCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "approve <node-id>",
		Short: "Approve a pending node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := forgedb.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.ApproveNode(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "OK  node %s approved\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to forge database")
	return cmd
}

func nodesRevokeCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "revoke <node-id>",
		Short: "Revoke an enrolled node (stops pack delivery and heartbeats)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := forgedb.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.RevokeNode(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "OK  node %s revoked\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to forge database")
	return cmd
}

func nodesAssignPackCmd() *cobra.Command {
	var dbPath string
	var packName string
	cmd := &cobra.Command{
		Use:   "assign-pack <node-id>",
		Short: "Assign a registered pack to a node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if packName == "" {
				return fmt.Errorf("--pack is required")
			}
			db, err := forgedb.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.AssignPack(args[0], packName, "operator"); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "OK  node %s → pack %s\n", args[0], packName)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to forge database")
	cmd.Flags().StringVar(&packName, "pack", "", "name of the registered pack to assign")
	return cmd
}

// ── forge pack register ───────────────────────────────────────────────────────

func packRegisterCmd() *cobra.Command {
	var dbPath string
	var packFile string
	cmd := &cobra.Command{
		Use:   "register <name>",
		Short: "Register a signed pack file in the Forge database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if packFile == "" {
				return fmt.Errorf("--file is required")
			}
			content, err := os.ReadFile(packFile)
			if err != nil {
				return fmt.Errorf("read pack: %w", err)
			}
			db, err := forgedb.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.RegisterPack(args[0], content); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "OK  pack %q registered (%d bytes)\n", args[0], len(content))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to forge database")
	cmd.Flags().StringVarP(&packFile, "file", "f", "", "path to the signed pack YAML file")
	return cmd
}
