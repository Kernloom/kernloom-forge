// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// forge is the Kernloom policy compiler CLI.
//
// Commands:
//
//	forge compile --policy <file> --manifests <dir> --mappings <dir>
//	forge validate --policy <file>
//	forge validate-manifest --manifest <file>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/pkg/compiler"
	"github.com/kernloom/kernloom-forge/pkg/core/capability"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/mapping"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
)

func main() {
	root := &cobra.Command{
		Use:   "forge",
		Short: "Kernloom policy compiler — translates enterprise intent into target plans",
	}

	root.AddCommand(compileCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(validateManifestCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// compileCmd implements: forge compile --policy <file> --manifests <dir> --mappings <dir>
func compileCmd() *cobra.Command {
	var policyFile string
	var manifestsDir string
	var mappingsDir string
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile a policy against capability manifests and produce reports",
		Example: `  forge compile \
    --policy examples/policies/investor-apps-access.yaml \
    --manifests examples/manifests/ \
    --mappings examples/mappings/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Load policy — peek kind first, then dispatch to typed parser.
			env, err := intent.LoadEnvelopeFromFile(policyFile)
			if err != nil {
				return fmt.Errorf("policy: %w", err)
			}
			if env.Kind != intent.KindAccessPolicy {
				return fmt.Errorf("unsupported policy kind %q (only AccessPolicy is supported in this release)", env.Kind)
			}
			policy, err := intent.LoadAccessPolicyFromFile(policyFile)
			if err != nil {
				return fmt.Errorf("policy: %w", err)
			}

			// 2. Extract requirements.
			reqs, err := requirement.Extract(policy)
			if err != nil {
				return fmt.Errorf("requirement extraction: %w", err)
			}

			// 3. Load capability manifests.
			manifests, err := loadManifests(manifestsDir)
			if err != nil {
				return fmt.Errorf("manifests: %w", err)
			}
			if len(manifests) == 0 {
				return fmt.Errorf("no CapabilityManifests found in %s", manifestsDir)
			}

			// 4. Load requirement mappings (optional per target).
			mappings, err := loadMappings(mappingsDir)
			if err != nil {
				return fmt.Errorf("mappings: %w", err)
			}

			// 5. Assemble TargetInputs.
			// MappingKey() uses adapterRef when set, otherwise metadata.name.
			// This allows "openziti-config-only" to share the "openziti" mapping.
			targets := make([]compiler.TargetInput, 0, len(manifests))
			for _, m := range manifests {
				ti := compiler.TargetInput{Manifest: m}
				if mp, ok := mappings[m.MappingKey()]; ok {
					ti.Mapping = mp
				}
				targets = append(targets, ti)
			}

			// 6. Compile.
			reports := compiler.Compile(policy.Metadata.Name, reqs, targets)

			// 7. Output.
			switch outputFormat {
			case "summary":
				fmt.Print(reports.Summary())
			case "yaml":
				if err := printYAML(reports); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown output format %q (use summary or yaml)", outputFormat)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&policyFile, "policy", "", "path to AccessPolicy YAML file (required)")
	cmd.Flags().StringVar(&manifestsDir, "manifests", "", "directory containing CapabilityManifest YAML files (required)")
	cmd.Flags().StringVar(&mappingsDir, "mappings", "", "directory containing RequirementMapping YAML files (optional)")
	cmd.Flags().StringVar(&outputFormat, "output", "summary", "output format: summary | yaml")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("manifests")

	return cmd
}

// validateCmd implements: forge validate --policy <file>
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

	cmd.Flags().StringVar(&policyFile, "policy", "", "path to AccessPolicy YAML file (required)")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

// validateManifestCmd implements: forge validate-manifest --manifest <file>
func validateManifestCmd() *cobra.Command {
	var manifestFile string

	cmd := &cobra.Command{
		Use:   "validate-manifest",
		Short: "Validate a CapabilityManifest file",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := capability.LoadFromFile(manifestFile)
			if err != nil {
				return err
			}
			fmt.Printf("OK: CapabilityManifest %q (%s) is valid\n", m.Metadata.Name, m.Spec.TargetType)
			return nil
		},
	}

	cmd.Flags().StringVar(&manifestFile, "manifest", "", "path to CapabilityManifest YAML file (required)")
	_ = cmd.MarkFlagRequired("manifest")
	return cmd
}

// loadManifests reads all *.yaml files in dir that are CapabilityManifests.
func loadManifests(dir string) ([]*capability.CapabilityManifest, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []*capability.CapabilityManifest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		m, err := capability.LoadFromFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, m)
	}
	return out, nil
}

// loadMappings reads all *.yaml files in dir that are RequirementMappings,
// keyed by their metadata.target.
func loadMappings(dir string) (map[string]*mapping.RequirementMapping, error) {
	out := make(map[string]*mapping.RequirementMapping)
	if dir == "" {
		return out, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		m, err := mapping.LoadFromFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out[m.Metadata.Target] = m
	}
	return out, nil
}

// printYAML serialises the reports to stdout as YAML.
func printYAML(reports interface{}) error {
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(reports); err != nil {
		return fmt.Errorf("encoding YAML: %w", err)
	}
	return enc.Close()
}
