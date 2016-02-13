package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/spazbite187/snatchtls/net"
)

type Args struct {
	TrustList, Url string
	Test bool
}

// package constants
const (
	VERSION = "1.0.0-SNAPSHOT"
)

func main() {
	// start app timer
	appTime := time.Now()
	fmt.Printf("Snatch TLS\n version %s\n\n", VERSION)

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
		test      = flag.Bool("test", false, "when enabled, all ciphers will be tested")
	)
	flag.Parse()
	args := Args{*trustList, *url, *test}

	// run default connection
	DefaultConnection(args)

	// if test true, run with all configured ciphers
	if args.Test {
		for key, value := range net.CipherMap {
			fmt.Printf("\nTrying with %s\n", key)
			SpecificConnection(args, value)
		}
	}
	// end app timer and print out total time
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
