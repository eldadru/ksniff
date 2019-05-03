package main

import (
	"github.com/spf13/pflag"
	"ksniff/pkg/cmd"
	"os"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-sniff", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := cmd.NewCmdSniff()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
