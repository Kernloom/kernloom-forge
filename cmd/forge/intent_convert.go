// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"os"

	"github.com/kernloom/kernloom-forge/pkg/core/naturalintent"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func intentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intent",
		Short: "Convert natural policy intent into canonical policy YAML",
	}
	cmd.AddCommand(intentConvertCmd())
	return cmd
}

func intentConvertCmd() *cobra.Command {
	var input, output, name, owner, subjectType, resourceType string

	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Convert a natural .intent file into AccessPolicy YAML",
		Example: `  forge intent convert \
    --input examples/policies/protect-ziti-controller.intent \
    --output /tmp/protect-ziti-controller.yaml \
    --owner security`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(input)
			if err != nil {
				return err
			}
			result, err := naturalintent.Convert(raw, naturalintent.Options{
				Name:                name,
				Owner:               owner,
				DefaultSubjectType:  subjectType,
				DefaultResourceType: resourceType,
			})
			if err != nil {
				return err
			}
			for _, warning := range result.Warnings {
				fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
			}
			out, err := yaml.Marshal(result.Policy)
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				_, err = os.Stdout.Write(out)
				return err
			}
			return os.WriteFile(output, out, 0o644)
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "natural policy intent file (required)")
	cmd.Flags().StringVar(&output, "output", "-", "AccessPolicy YAML output path, or '-' for stdout")
	cmd.Flags().StringVar(&name, "name", "", "override metadata.name")
	cmd.Flags().StringVar(&owner, "owner", "", "metadata.owner")
	cmd.Flags().StringVar(&subjectType, "default-subject-type", "group", "selector type for untyped subjects")
	cmd.Flags().StringVar(&resourceType, "default-resource-type", "endpoint", "selector type for untyped resources")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}
