// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"os"
	"time"

	corecontext "github.com/kernloom/kernloom-forge/pkg/core/context"
	"github.com/kernloom/kernloom-forge/pkg/core/risk"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func contextCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Context snapshot and fixture helpers",
	}
	cmd.AddCommand(contextFixtureSnapshotCmd())
	return cmd
}

func contextFixtureSnapshotCmd() *cobra.Command {
	var output, nowText string
	cmd := &cobra.Command{
		Use:   "fixture-snapshot",
		Short: "Write a deterministic enterprise IdP/CMDB/PIP fixture ContextSnapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			now, err := parseOptionalRFC3339(nowText)
			if err != nil {
				return err
			}
			snapshot := corecontext.EnterpriseContextFixtureSnapshot(now)
			return writeYAML(output, snapshot)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	cmd.Flags().StringVar(&nowText, "now", "", "fixed RFC3339 timestamp for deterministic output")
	return cmd
}

func riskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk model and deterministic evaluation helpers",
	}
	cmd.AddCommand(riskFixtureModelCmd())
	cmd.AddCommand(riskEvaluateCmd())
	return cmd
}

func riskFixtureModelCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "fixture-model",
		Short: "Write the deterministic fixture RiskModel",
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeYAML(output, risk.FixtureModel())
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	return cmd
}

func riskEvaluateCmd() *cobra.Command {
	var snapshotPath, modelPath, output, nowText string
	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate a RiskModel against a ContextSnapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			now, err := parseOptionalRFC3339(nowText)
			if err != nil {
				return err
			}
			if now.IsZero() {
				now = time.Now().UTC()
			}
			snapshot, err := loadContextSnapshot(snapshotPath)
			if err != nil {
				return err
			}
			model := risk.FixtureModel()
			if modelPath != "" {
				model, err = risk.LoadModelFromFile(modelPath)
				if err != nil {
					return err
				}
			}
			result, err := risk.Evaluate(model, snapshot, nil, now)
			if err != nil {
				return err
			}
			return writeYAML(output, result)
		},
	}
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "ContextSnapshot YAML file (required)")
	cmd.Flags().StringVar(&modelPath, "model", "", "RiskModel YAML file (default: built-in fixture model)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	cmd.Flags().StringVar(&nowText, "now", "", "fixed RFC3339 timestamp for deterministic output")
	_ = cmd.MarkFlagRequired("snapshot")
	return cmd
}

func loadContextSnapshot(path string) (*corecontext.ContextSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading context snapshot %s: %w", path, err)
	}
	var snapshot corecontext.ContextSnapshot
	if err := yaml.Unmarshal(raw, &snapshot); err != nil {
		return nil, fmt.Errorf("parsing context snapshot %s: %w", path, err)
	}
	if snapshot.ID == "" {
		return nil, fmt.Errorf("context snapshot %s: id is required", path)
	}
	return &snapshot, nil
}

func parseOptionalRFC3339(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("--now must be RFC3339: %w", err)
	}
	return t.UTC(), nil
}
