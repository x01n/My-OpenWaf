package main

import (
	"fmt"
	"os"

	"My-OpenWaf/internal/app"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-admin-password":
			if err := app.ResetAdminPassword(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "help", "-h", "--help":
			fmt.Fprintln(os.Stdout, "Usage:")
			fmt.Fprintln(os.Stdout, "  my-openwaf")
			fmt.Fprintln(os.Stdout, "  my-openwaf reset-admin-password [username] <new-password>")
			return
		}
	}
	app.Run()
}
