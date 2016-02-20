package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/spazbite187/snatchtls/client"
)

// Version contains details about the current version. BuildTime contains the current time.
// Commit contains the git commit hash. BuildNum contains a composite of the previous three.
var (
	Version   = " not defined "
	BuildTime = " not defined "
	Commit    = " not defined "
	BuildNum  = BuildTime + Commit
)

func main() {
	// start app timer
	appTime := time.Now()
	fmt.Printf("Snatch TLS\n version %s\n", Version)
	fmt.Printf("    build num:  %s\n", BuildNum)

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
		test      = flag.Bool("test", false, "when enabled, all ciphers will be tested")
	)
	flag.Parse()
	args := client.Arguments{
		TrustList: *trustList,
		URL:       *url,
		Test:      *test,
	}

	// if test true, run with all configured ciphers, else run default connection
	if args.Test {
		client.DefaultConnection(args)
		client.TestConnections(args)
	} else {
		client.DefaultConnection(args)
	}
	// end app timer and print out total time
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
