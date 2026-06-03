package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
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
	if bind := os.Getenv("MY_OPENWAF_PPROF_BIND"); bind != "" {
		go func() {
			log.Printf("pprof listening on %s", bind)
			if err := http.ListenAndServe(bind, nil); err != nil {
				log.Printf("pprof server stopped: %v", err)
			}
		}()
	}
	app.Run()
}
