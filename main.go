package main

import (
	"flag"
	"fmt"
	"time"
)

type arguments struct {
	TrustList, URL string
	Test           bool
}

// package constants
const (
	VERSION = "1.0.0-SNAPSHOT"
)

func main() {
	// start app timer
	appTime := time.Now()
	fmt.Printf("Snatch TLS\n version %s\n", VERSION)

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
		test      = flag.Bool("test", false, "when enabled, all ciphers will be tested")
	)
	flag.Parse()
	args := arguments{*trustList, *url, *test}

	// if test true, run with all configured ciphers, else run default connection
	if args.Test {
		DefaultConnection(args)
		TestConnections(args)
	} else {
		DefaultConnection(args)
	}
	// end app timer and print out total time
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
