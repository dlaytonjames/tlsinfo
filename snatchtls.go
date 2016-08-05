package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/spazbite187/snatchtls/client"
)

var version = "1.0.0-DEV"

func main() {
	appTime := time.Now() // start app timer
	fmt.Printf("Snatch TLS\n  version %s\n", version)

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
		save      = flag.String("s", "", "the filename for saving the server certificate")
		test      = flag.Bool("test", false, "when enabled, all ciphers will be tested")
	)
	flag.Parse()
	args := client.Arguments{
		TrustList: *trustList,
		URL:       *url,
		Test:      *test,
		Cert:      *save,
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
