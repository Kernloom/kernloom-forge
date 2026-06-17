// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler CLI.
//
// Commands:
//
//	forge compile --policy <file> --adapters <dir> --profiles <dir> [--output summary|yaml]
//	forge validate --policy <file>
//	forge validate-adapter --adapter <file>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
