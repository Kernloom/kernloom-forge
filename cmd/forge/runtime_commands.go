// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/signing"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/compiler"
	"github.com/kernloom/kernloom-forge/pkg/configpdp"
	conformancefixtures "github.com/kernloom/kernloom-forge/pkg/conformance"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
	"github.com/kernloom/kernloom-forge/pkg/report"
	"github.com/spf13/cobra"
)

func exportRuntimePolicyCmd() *cobra.Command {
	var policyFile, adaptersDir, profilesDir, target, output string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "export-runtime-policy",
		Short: "Compile a KLIQ RuntimePolicyPack from an AccessPolicy and target profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, plans, profiles, err := compilePlans(policyFile, adaptersDir, profilesDir)
			if err != nil {
				return err
			}
			ep, prof, err := selectTarget(plans, profiles, target)
			if err != nil {
				return err
			}
			pack, err := bundler.BuildPolicyPack(ep, prof, bundler.RuntimePolicyConfig{
				Name:       pol.Metadata.Name + "-" + prof.Metadata.Name,
				IssuedAt:   time.Now().UTC(),
				DefaultTTL: ttl,
			})
			if err != nil {
				return err
			}
			return writeYAML(output, pack)
		},
	}
	addCompileFlags(cmd, &policyFile, &adaptersDir, &profilesDir)
	cmd.Flags().StringVar(&target, "target", "", "TargetIntegrationProfile metadata.name (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "default runtime action TTL (default depends on target mode)")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func buildRuntimeBundleCmd() *cobra.Command {
	var policyFile, adaptersDir, profilesDir, target, output, signingKey, keyID, nodeID, mode, failover string
	var generation int
	var validFor, ttl time.Duration
	cmd := &cobra.Command{
		Use:   "build-runtime-bundle",
		Short: "Build and sign a KLIQ RuntimeBundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, plans, profiles, err := compilePlans(policyFile, adaptersDir, profilesDir)
			if err != nil {
				return err
			}
			ep, prof, err := selectTarget(plans, profiles, target)
			if err != nil {
				return err
			}
			priv, err := signing.LoadPrivateKey(signingKey)
			if err != nil {
				return err
			}
			b, err := bundler.Build(ep, prof, bundler.BundleConfig{
				NodeID:            nodeID,
				Generation:        generation,
				IssuedAt:          time.Now().UTC(),
				ValidFor:          validFor,
				PreferredAdapters: []string{prof.Spec.AdapterRef},
				RuntimePDPMode:    mode,
				FailoverBehavior:  failover,
				DefaultTTL:        ttl,
			}, priv)
			if err != nil {
				return err
			}
			if keyID != "" {
				b.Signature.KeyID = keyID
			}
			return writeYAML(output, b)
		},
	}
	addCompileFlags(cmd, &policyFile, &adaptersDir, &profilesDir)
	cmd.Flags().StringVar(&target, "target", "", "TargetIntegrationProfile metadata.name (required)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "KLIQ node ID (required)")
	cmd.Flags().IntVar(&generation, "generation", 1, "bundle generation")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "PEM Ed25519 private key (required)")
	cmd.Flags().StringVar(&keyID, "key-id", "forge-runtime", "signature key ID")
	cmd.Flags().StringVar(&mode, "runtime-pdp-mode", "active", "runtime PDP mode encoded in bundle")
	cmd.Flags().StringVar(&failover, "failover", "fail_static", "offline failover behavior")
	cmd.Flags().DurationVar(&validFor, "valid-for", 24*time.Hour, "bundle validity duration")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "default runtime action TTL")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("node-id")
	_ = cmd.MarkFlagRequired("signing-key")
	return cmd
}

func configPDPCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config-pdp", Short: "Config PDP validation commands"}
	cmd.AddCommand(configPDPValidateCmd())
	return cmd
}

func configPDPValidateCmd() *cobra.Command {
	var policyFile, adaptersDir, profilesDir, target, output string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate compiled target plan against AccessPolicy enforcementConstraints",
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, plans, _, err := compilePlans(policyFile, adaptersDir, profilesDir)
			if err != nil {
				return err
			}
			selected := plans
			if target != "" {
				p, _, err := selectTarget(plans, nil, target)
				if err != nil {
					return err
				}
				selected = []*plan.EnforcementPlan{p}
			}
			var reports []configpdp.ValidationReport
			deny := false
			for _, p := range selected {
				r := configpdp.Validate(pol, p)
				if r.Spec.Result == configpdp.ResultDeny {
					deny = true
				}
				reports = append(reports, r)
			}
			if err := writeYAML(output, reports); err != nil {
				return err
			}
			if deny {
				return fmt.Errorf("config-pdp denied one or more target plans")
			}
			return nil
		},
	}
	addCompileFlags(cmd, &policyFile, &adaptersDir, &profilesDir)
	cmd.Flags().StringVar(&target, "target", "", "optional TargetIntegrationProfile metadata.name")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	return cmd
}

func reportCmd() *cobra.Command {
	var policyFile, adaptersDir, profilesDir, output string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Emit coverage, delegation, downgrade and Config PDP reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, plans, _, err := compilePlans(policyFile, adaptersDir, profilesDir)
			if err != nil {
				return err
			}
			validations := make([]configpdp.ValidationReport, 0, len(plans))
			for _, p := range plans {
				validations = append(validations, configpdp.Validate(pol, p))
			}
			return writeYAML(output, report.Build(pol.Metadata.Name, plans, validations))
		},
	}
	addCompileFlags(cmd, &policyFile, &adaptersDir, &profilesDir)
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	return cmd
}

func keygenCmd() *cobra.Command {
	var privatePath, publicPath string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for signing runtime bundles",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := signing.GenerateKeyPair()
			if err != nil {
				return err
			}
			if privatePath == "" || publicPath == "" {
				return fmt.Errorf("--private and --public are required")
			}
			if err := signing.SavePrivateKey(privatePath, priv); err != nil {
				return err
			}
			if err := signing.SavePublicKey(publicPath, pub); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&privatePath, "private", "", "private key output path")
	cmd.Flags().StringVar(&publicPath, "public", "", "public key output path")
	return cmd
}

func conformanceFixturesCmd() *cobra.Command {
	var outputDir string
	cmd := &cobra.Command{
		Use:   "conformance-fixtures",
		Short: "Write KLIQ/Forge runtime contract conformance fixtures",
		RunE: func(cmd *cobra.Command, args []string) error {
			return conformancefixtures.Write(outputDir, time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC))
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func addCompileFlags(cmd *cobra.Command, policyFile, adaptersDir, profilesDir *string) {
	cmd.Flags().StringVar(policyFile, "policy", "", "AccessPolicy YAML file (required)")
	cmd.Flags().StringVar(adaptersDir, "adapters", "", "directory of adapter subdirectories (required)")
	cmd.Flags().StringVar(profilesDir, "profiles", "", "directory of TargetIntegrationProfile YAML files (required)")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("adapters")
	_ = cmd.MarkFlagRequired("profiles")
}

func compilePlans(policyFile, adaptersDir, profilesDir string) (*intent.AccessPolicy, []*plan.EnforcementPlan, []*profile.TargetIntegrationProfile, error) {
	env, err := intent.LoadEnvelopeFromFile(policyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("policy: %w", err)
	}
	if env.Kind != intent.KindAccessPolicy {
		return nil, nil, nil, fmt.Errorf("unsupported policy kind %q", env.Kind)
	}
	pol, err := intent.LoadAccessPolicyFromFile(policyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("policy: %w", err)
	}
	reqs, err := requirement.Extract(pol)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("requirement extraction: %w", err)
	}
	profiles, err := loadProfiles(profilesDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("profiles: %w", err)
	}
	if len(profiles) == 0 {
		return nil, nil, nil, fmt.Errorf("no TargetIntegrationProfiles found in %s", profilesDir)
	}
	bundles, err := loadBundles(adaptersDir, profiles)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("adapters: %w", err)
	}
	return pol, compiler.Compile(pol.Metadata.Name, reqs, profiles, bundles), profiles, nil
}

func selectTarget(plans []*plan.EnforcementPlan, profiles []*profile.TargetIntegrationProfile, target string) (*plan.EnforcementPlan, *profile.TargetIntegrationProfile, error) {
	var selectedPlan *plan.EnforcementPlan
	for _, p := range plans {
		if p.Metadata.Target == target {
			selectedPlan = p
			break
		}
	}
	if selectedPlan == nil {
		return nil, nil, fmt.Errorf("target %q not found", target)
	}
	var selectedProfile *profile.TargetIntegrationProfile
	for _, p := range profiles {
		if p.Metadata.Name == target {
			selectedProfile = p
			break
		}
	}
	if selectedProfile == nil && profiles != nil {
		return nil, nil, fmt.Errorf("profile %q not found", target)
	}
	return selectedPlan, selectedProfile, nil
}

func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func loadSigningKeyOrEphemeral(path string) (ed25519.PrivateKey, error) {
	if path != "" {
		return signing.LoadPrivateKey(path)
	}
	_, priv, err := signing.GenerateKeyPair()
	return priv, err
}
