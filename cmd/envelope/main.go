package main

import (
	"github.com/spf13/cobra"
)

const (
	FlagDebugMode = "debug"
)

var cmd = &cobra.Command{
	Use:   "envelope",
	Short: "Envelope System",
}

func main() {
	// cmd.AddCommand(commands.Generate)
	cmd.Execute()
}
