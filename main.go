package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spazbite187/snatchtls/common"
	"golang.org/x/crypto/ocsp"
)

type Args struct {
	TrustList, Url string
}

// package constants
const (
	VERSION = "1.0-SNAPSHOT"
)

func main() {
	// start app timer
	appTime := time.Now()

	// flag setup
	var (
		trustList = flag.String("trst", "trustList.pem", " the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("url", "https://www.google.com", "the url used for the connection")
	)
	flag.Parse()
	args := Args{*trustList, *url}

	// print out intro and args
	fmt.Printf("Snatch TLS\n version %s\n\n", VERSION)
	fmt.Printf("  trust list: %s\n", args.TrustList)
	fmt.Printf("         url: %s\n", args.Url)

	// Get trust list
	trustedCAs, err := common.GetTrustedCAs(args.TrustList)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Get TLS configuration
	tlsConfig := common.GetTlsConfig(trustedCAs)

	// Get http client
	client := common.GetHttpClient(tlsConfig)

	// start request timer
	reqTimer := time.Now()
	// perform http GET request
	resp, err := client.Get(args.Url)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	// end request timer
	reqTime := time.Since(reqTimer)

	// check response
	if resp.StatusCode != 200 {
		fmt.Println(err)
		os.Exit(1)
	}
	// check TLS connection
	tlsConnState := resp.TLS
	if tlsConnState == nil {
		err = errors.New("TLS connection failed")
		fmt.Println(err)
		os.Exit(1)
	}

	// Check for stapled OCSP response
	stapledOcspResponse := false
	ocspResp := tlsConnState.OCSPResponse
	if len(ocspResp) > 0 {
		stapledOcspResponse = true
		ocsp, err := ocsp.ParseResponse(ocspResp, nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("OCSP status: ", ocsp.Status)
	}

	// get cipher name
	cipher := common.GetCipherName(tlsConnState.CipherSuite)
	// get tls version name
	tlsVersion := common.GetTlsName(tlsConnState.Version)
	// get server cert subject name
	peerCerts := tlsConnState.PeerCertificates
	srvCert := peerCerts[0]
	subjectDN := common.GetSubjectDn(srvCert)

	// print out data
	fmt.Println("\nResponse time: ", reqTime)
	fmt.Println("HTTP response status: ", resp.Status)
	fmt.Println("HTTP protocol: ", resp.Proto)
	fmt.Println("TLS version: ", tlsVersion)
	fmt.Println("TLS cipher: ", cipher)
	fmt.Println("Server certificate:")
	fmt.Println("  Subject DN:")
	fmt.Printf("      CN=%s\n", subjectDN.CN)
	fmt.Printf("       O=%s\n", subjectDN.O)
	fmt.Printf("       C=%s\n", subjectDN.C)
	sanDns := srvCert.DNSNames
	for cnt, dnsName := range sanDns {
		cnt++
		fmt.Printf("[%d] DNSName: %s\n", cnt, dnsName)
	}
	sanIPs := srvCert.IPAddresses
	for cnt, ip := range sanIPs {
		cnt++
		fmt.Printf("[%d] IPAddress: %v\n", cnt, ip)
	}
	fmt.Printf("Stapled OCSP response: %v\n", stapledOcspResponse)

	// end app timer
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
