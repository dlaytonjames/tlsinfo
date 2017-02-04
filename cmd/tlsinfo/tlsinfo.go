// Command tlsinfo ...
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/spazbite187/tlsinfo"
)

var version = "1.0.0"

func main() {
	appTime := time.Now() // start app timer
	fmt.Printf("TLS Info\n  version %s\n", version)

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
		save      = flag.String("s", "", "the filename for saving the server certificate")
		test      = flag.Bool("test", false, "when enabled, all ciphers will be tested")
	)
	flag.Parse()
	args := tlsinfo.Arguments{
		TrustList: *trustList,
		URL:       *url,
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
	// end app timer and print out total time
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
