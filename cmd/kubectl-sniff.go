package main

import (
	"ksniff/pkg/cmd"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-sniff", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := cmd.NewCmdSniff(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
