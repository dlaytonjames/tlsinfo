// Command tlsinfo ...
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/spazbite187/tlsinfo"
)

var version = "1.0.0"

func main() {
	fmt.Printf("TLS Info\n  version %s\n", version)
	if len(os.Args) < 2 {
		fmt.Printf("\nError - hostname required. Example: tlsinfo www.google.com\n\n")
		os.Exit(1)
	}
	url := "https://" + os.Args[1]

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		save      = flag.String("s", "", "the filename for saving the server certificate")
		test      = flag.Bool("test", false, "when enabled, all ciphers will be tested")
	)
	flag.Parse()
	args := tlsinfo.Arguments{
		TrustList: *trustList,
		URL:       url,
		Test:      *test,
		Cert:      *save,
	}

	// if test true, run with all configured ciphers, else run default connection
	if args.Test {
		tlsinfo.DefaultConnection(args)
		tlsinfo.TestConnections(args)
	} else {
		tlsinfo.DefaultConnection(args)
	}
	fmt.Println()
}
