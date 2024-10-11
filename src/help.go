package main

import (
	"flag"
	"fmt"
	"os"
)

func defaultHelpUsage() {
	intro := `
Использование:
  masscsr [flags]`
	fmt.Fprintln(os.Stderr, intro)

	fmt.Fprintln(os.Stderr, "\nFlags:")
	flag.PrintDefaults()

	fmt.Fprintln(os.Stderr)
}
