// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler CLI.
//
// Commands:
//
//	forge compile --policy <file> --adapters <dir> --profiles <dir> [--output summary|yaml]
//	forge validate --policy <file>
//	forge validate-adapter --adapter <file>
//	forge serve --addr :8443 [--policy <file>] [--adapters <dir>] [--profiles <dir>] [--target <profile>] [--signing-key <key>]
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/api"
	"github.com/kernloom/kernloom-forge/internal/enrollment"
	"github.com/kernloom/kernloom-forge/internal/signing"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/compiler"
	"github.com/kernloom/kernloom-forge/pkg/core/action"
	"github.com/kernloom/kernloom-forge/pkg/core/adapter"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/mapping"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
)

func main() {
	root := &cobra.Command{
		Use:   "forge",
		Short: "Kernloom policy compiler — translates enterprise intent into enforcement plans",
	}
	root.AddCommand(compileCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(validateAdapterCmd())
	root.AddCommand(exportRuntimePolicyCmd())
	root.AddCommand(buildRuntimeBundleCmd())
	root.AddCommand(configPDPCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(keygenCmd())
	root.AddCommand(enrollTokenCmd())
	root.AddCommand(conformanceFixturesCmd())
	root.AddCommand(serveCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// serveCmd: forge serve --addr :8443
func serveCmd() *cobra.Command {
	var addr, adaptersDir, profilesDir, policyFile, target, signingKey, runtimeMode, failover, enrollTokenStore string
	var enrollTokens []string
	var generation int
	var validFor, ttl time.Duration

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Forge control-plane API server",
		Example: `  forge serve --addr :8443 \
    --policy examples/policies/investor-apps-access.yaml \
    --adapters examples/adapters/ \
    --profiles examples/profiles/ \
    --target openziti-production \
    --signing-key /tmp/forge-runtime.key \
    --enroll-token-store /var/lib/kernloom/forge-enroll-tokens.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srvLog := log.New(os.Stderr, "[forge-api] ", log.LstdFlags)
			if len(enrollTokens) == 0 && enrollTokenStore == "" {
				return fmt.Errorf("forge serve requires --enroll-token or --enroll-token-store")
			}

			var tokenValidator func(nodeID, token string) error
			if enrollTokenStore != "" {
				store, err := enrollment.Load(enrollTokenStore)
				if err != nil {
					return err
				}
				tokenValidator = store.Consume
				srvLog.Printf("using enrollment token store %s", enrollTokenStore)
			}

			var provider api.BundleProvider
			if adaptersDir != "" && profilesDir != "" && policyFile != "" && target != "" {
				priv, err := signing.LoadPrivateKey(signingKey)
				if err != nil {
					return err
				}
				provider = func(ctx context.Context, nodeID string) ([]byte, error) {
					_, plans, profiles, err := compilePlans(policyFile, adaptersDir, profilesDir)
					if err != nil {
						return nil, err
					}
					ep, prof, err := selectTarget(plans, profiles, target)
					if err != nil {
						return nil, err
					}
					b, err := bundler.Build(ep, prof, bundler.BundleConfig{
						NodeID:            nodeID,
						Generation:        generation,
						IssuedAt:          time.Now().UTC(),
						ValidFor:          validFor,
						PreferredAdapters: []string{prof.Spec.AdapterRef},
						RuntimePDPMode:    runtimeMode,
						FailoverBehavior:  failover,
						DefaultTTL:        ttl,
					}, priv)
					if err != nil {
						return nil, err
					}
					srvLog.Printf("bundle request node=%s target=%s generation=%d", nodeID, target, generation)
					return yaml.Marshal(b)
				}
			}

			srv := api.NewServerWithOptions(provider, srvLog, api.ServerOptions{
				EnrollTokens:         enrollTokens,
				RequireAuth:          true,
				EnrollTokenValidator: tokenValidator,
			})
			srvLog.Printf("forge API server listening on %s", addr)
			return http.ListenAndServe(addr, srv.Handler())
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8443", "listen address")
	cmd.Flags().StringVar(&policyFile, "policy", "", "AccessPolicy YAML file (enables real bundle generation)")
	cmd.Flags().StringVar(&adaptersDir, "adapters", "", "adapters directory")
	cmd.Flags().StringVar(&profilesDir, "profiles", "", "profiles directory")
	cmd.Flags().StringVar(&target, "target", "", "TargetIntegrationProfile metadata.name for generated bundles")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "PEM Ed25519 private key for generated bundles")
	cmd.Flags().IntVar(&generation, "generation", 1, "bundle generation")
	cmd.Flags().DurationVar(&validFor, "valid-for", 24*time.Hour, "bundle validity duration")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "default runtime action TTL")
	cmd.Flags().StringVar(&runtimeMode, "runtime-pdp-mode", "active", "runtime PDP mode encoded in bundle")
	cmd.Flags().StringVar(&failover, "failover", "fail_static", "offline failover behavior")
	cmd.Flags().StringArrayVar(&enrollTokens, "enroll-token", nil, "bootstrap enrollment token accepted by forge serve (repeatable)")
	cmd.Flags().StringVar(&enrollTokenStore, "enroll-token-store", "", "YAML store of pre-registered node enrollment tokens")
	return cmd
}

func enrollTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll-token",
		Short: "Manage KLIQ node enrollment tokens",
	}
	cmd.AddCommand(enrollTokenCreateCmd())
	return cmd
}

func enrollTokenCreateCmd() *cobra.Command {
	var storePath, nodeID, description string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Pre-register a KLIQ node and print its one-time enrollment token",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := enrollment.Load(storePath)
			if err != nil {
				return err
			}
			raw, rec, err := store.Create(nodeID, ttl, description)
			if err != nil {
				return err
			}
			fmt.Printf("node_id: %s\n", rec.NodeID)
			fmt.Printf("enroll_token: %s\n", raw)
			fmt.Printf("store: %s\n", storePath)
			if !rec.ExpiresAt.IsZero() {
				fmt.Printf("expires_at: %s\n", rec.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "YAML enrollment token store path (required)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "KLIQ node ID to pre-register (required)")
	cmd.Flags().DurationVar(&ttl, "ttl", 24*time.Hour, "token validity duration; 0 means no expiry")
	cmd.Flags().StringVar(&description, "description", "", "optional operator note")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("node-id")
	return cmd
}

// compileCmd: forge compile --policy <file> --adapters <dir> --profiles <dir>
//
// --adapters <dir> contains one subdirectory per adapter (named after adapterRef):
//
//	adapters/openziti/capability.yaml
//	adapters/openziti/mappings.yaml
//	adapters/openziti/actions.yaml  (optional)
//
// --profiles <dir> contains TargetIntegrationProfile YAML files.
func compileCmd() *cobra.Command {
	var policyFile, adaptersDir, profilesDir, outputFmt string

	cmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile a policy against integration profiles",
		Example: `  forge compile \
    --policy  examples/policies/investor-apps-access.yaml \
    --adapters examples/adapters/ \
    --profiles examples/profiles/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Load and dispatch policy.
			env, err := intent.LoadEnvelopeFromFile(policyFile)
			if err != nil {
				return fmt.Errorf("policy: %w", err)
			}
			if env.Kind != intent.KindAccessPolicy {
				return fmt.Errorf("unsupported policy kind %q", env.Kind)
			}
			pol, err := intent.LoadAccessPolicyFromFile(policyFile)
			if err != nil {
				return fmt.Errorf("policy: %w", err)
			}

			// 2. Extract requirements.
			reqs, err := requirement.Extract(pol)
			if err != nil {
				return fmt.Errorf("requirement extraction: %w", err)
			}

			// 3. Load profiles.
			profiles, err := loadProfiles(profilesDir)
			if err != nil {
				return fmt.Errorf("profiles: %w", err)
			}
			if len(profiles) == 0 {
				return fmt.Errorf("no TargetIntegrationProfiles found in %s", profilesDir)
			}

			// 4. Load adapter bundles (one per unique adapterRef).
			bundles, err := loadBundles(adaptersDir, profiles)
			if err != nil {
				return fmt.Errorf("adapters: %w", err)
			}

			// 5. Compile.
			plans := compiler.Compile(pol.Metadata.Name, reqs, profiles, bundles)

			// 6. Output.
			switch outputFmt {
			case "summary":
				for _, p := range plans {
					fmt.Println(p.Summary())
				}
			case "yaml":
				enc := yaml.NewEncoder(os.Stdout)
				enc.SetIndent(2)
				for _, p := range plans {
					if err := enc.Encode(p); err != nil {
						return err
					}
				}
				_ = enc.Close()
			default:
				return fmt.Errorf("unknown output format %q (use summary or yaml)", outputFmt)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&policyFile, "policy", "", "AccessPolicy YAML file (required)")
	cmd.Flags().StringVar(&adaptersDir, "adapters", "", "directory of adapter subdirectories (required)")
	cmd.Flags().StringVar(&profilesDir, "profiles", "", "directory of TargetIntegrationProfile YAML files (required)")
	cmd.Flags().StringVar(&outputFmt, "output", "summary", "output format: summary | yaml")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("adapters")
	_ = cmd.MarkFlagRequired("profiles")
	return cmd
}

// validateCmd: forge validate --policy <file>
func validateCmd() *cobra.Command {
	var policyFile string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate an AccessPolicy file",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := intent.LoadEnvelopeFromFile(policyFile)
			if err != nil {
				return err
			}
			switch env.Kind {
			case intent.KindAccessPolicy:
				p, err := intent.LoadAccessPolicyFromFile(policyFile)
				if err != nil {
					return err
				}
				fmt.Printf("OK: AccessPolicy %q is valid\n", p.Metadata.Name)
			default:
				return fmt.Errorf("unsupported policy kind %q", env.Kind)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policyFile, "policy", "", "AccessPolicy YAML file (required)")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

// validateAdapterCmd: forge validate-adapter --adapter <file>
func validateAdapterCmd() *cobra.Command {
	var adapterFile string
	cmd := &cobra.Command{
		Use:   "validate-adapter",
		Short: "Validate an AdapterCapabilityManifest file",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := adapter.LoadFromFile(adapterFile)
			if err != nil {
				return err
			}
			fmt.Printf("OK: AdapterCapabilityManifest %q (%s) is valid\n", m.Metadata.Name, m.Spec.TargetType)
			return nil
		},
	}
	cmd.Flags().StringVar(&adapterFile, "adapter", "", "AdapterCapabilityManifest YAML file (required)")
	_ = cmd.MarkFlagRequired("adapter")
	return cmd
}

// loadProfiles reads all TargetIntegrationProfile YAML files from dir.
func loadProfiles(dir string) ([]*profile.TargetIntegrationProfile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []*profile.TargetIntegrationProfile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p, err := profile.LoadFromFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, p)
	}
	return out, nil
}

// loadBundles loads one TargetBundle per unique adapterRef found in profiles.
// Adapter files are loaded from: <adaptersDir>/<adapterRef>/capability.yaml etc.
func loadBundles(adaptersDir string, profiles []*profile.TargetIntegrationProfile) (map[string]*compiler.TargetBundle, error) {
	seen := map[string]bool{}
	for _, p := range profiles {
		seen[p.Spec.AdapterRef] = true
	}

	bundles := map[string]*compiler.TargetBundle{}
	for ref := range seen {
		base := filepath.Join(adaptersDir, ref)
		bundle, err := loadBundle(base, ref)
		if err != nil {
			return nil, fmt.Errorf("adapter %q: %w", ref, err)
		}
		bundles[ref] = bundle
	}
	return bundles, nil
}

// loadBundle loads a TargetBundle from a single adapter directory.
func loadBundle(dir, ref string) (*compiler.TargetBundle, error) {
	b := &compiler.TargetBundle{}

	capPath := filepath.Join(dir, "capability.yaml")
	m, err := adapter.LoadFromFile(capPath)
	if err != nil {
		return nil, fmt.Errorf("capability.yaml: %w", err)
	}
	b.Adapter = m

	mapPath := filepath.Join(dir, "mappings.yaml")
	ms, err := mapping.LoadFromFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("mappings.yaml: %w", err)
	}
	b.Mappings = ms

	actPath := filepath.Join(dir, "actions.yaml")
	if _, err := os.Stat(actPath); err == nil {
		cat, err := action.LoadFromFile(actPath)
		if err != nil {
			return nil, fmt.Errorf("actions.yaml: %w", err)
		}
		b.Catalog = cat
	}

	_ = ref
	return b, nil
}
