// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler and registry validator.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

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
			fmt.Printf("OK  registry loaded: %d intents  %d capabilities  %d signals  %d granularities  %d adapter_types  %d compiler_rules\n",
				len(reg.Intents), len(reg.Capabilities), len(reg.Signals),
				len(reg.Granularities), len(reg.AdapterTypes), len(reg.CompilerRules))
			return nil
		},
	}
}

// ── forge adapter ─────────────────────────────────────────────────────────────

func adapterCmd() *cobra.Command {
	var registryDir string
	cmd := &cobra.Command{
		Use:   "adapter",
		Short: "Adapter manifest operations",
	}
	validateCmd := &cobra.Command{
		Use:   "validate <manifest.yaml>",
		Short: "Validate an adapter manifest against the core registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.LoadDir(registryDir)
			if err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			if err := validator.ValidateAdapterFile(args[0], reg); err != nil {
				return err
			}
			fmt.Printf("OK  adapter manifest %s is valid\n", args[0])
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
