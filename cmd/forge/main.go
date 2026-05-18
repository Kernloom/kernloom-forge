// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler and registry validator.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"log"
	"net/http"

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

// ── forge serve ───────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	var addr string
	var dbPath string
	var enrollKey string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Forge control-plane HTTP server",
		Long: `Start the Forge HTTP control-plane that KLIQ nodes enroll into.

Endpoints:
  POST /api/v1/nodes/enroll                  — KLIQ registers itself
  POST /api/v1/nodes/{id}/heartbeat          — periodic liveness + status
  GET  /api/v1/nodes/{id}/policy-pack        — pull assigned signed pack
  POST /api/v1/nodes/{id}/policy-pack/status — report pack apply result

Admin endpoints (bind to loopback in production):
  GET  /api/v1/nodes                         — list enrolled nodes
  POST /api/v1/nodes/{id}/approve            — approve a pending node
  POST /api/v1/packs?name=<n>               — register a signed pack (body = YAML)
  POST /api/v1/nodes/{id}/assign-pack?pack=  — assign a pack to a node

Example:
  forge serve --addr :8080 --db /var/lib/kernloom/forge.db --enroll-key secret123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := log.New(os.Stderr, "[forge-serve] ", log.LstdFlags)

			db, err := forgedb.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()
			logger.Printf("database: %s", dbPath)

			srv := forgeapi.New(db, enrollKey, logger)
			if enrollKey == "" {
				logger.Printf("WARNING: --enroll-key not set — API is open (dev mode)")
			}

			logger.Printf("listening on %s", addr)
			return http.ListenAndServe(addr, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/kernloom/forge.db", "path to SQLite database file")
	cmd.Flags().StringVar(&enrollKey, "enroll-key", "", "shared enrollment key (Bearer token); empty = open dev mode")
	return cmd
}
