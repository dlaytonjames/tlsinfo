package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/spazbite187/snatchtls/client"
)

func main() {
	// start app timer
	appTime := time.Now()
	fmt.Printf("Snatch TLS\n version %s\n", client.Version)
	fmt.Printf("    build num:  %s\n", client.BuildNum)

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
