// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler and registry validator.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/compiler"
	"github.com/kernloom/kernloom-forge/internal/packs"
	"github.com/kernloom/kernloom-forge/internal/registry"
	"github.com/kernloom/kernloom-forge/internal/validator"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
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
	return root
}

// ── forge registry ────────────────────────────────────────────────────────────

func registryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Registry operations",
	}
	cmd.AddCommand(registryValidateCmd())
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
			reg, err := registry.LoadDir(registryDir)
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
			reg, err := registry.LoadDir(registryDir)
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
	return cmd
}

// ── forge pack ────────────────────────────────────────────────────────────────

func packCmd() *cobra.Command {
	var registryDir string
	var nodesDir string
	var forgeURL string
	var outFile string

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
			reg, err := registry.LoadDir(registryDir)
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
			reg, err := registry.LoadDir(registryDir)
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
