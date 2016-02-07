package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spazbite187/snatchtls/common"
	"golang.org/x/crypto/ocsp"
)

type Args struct {
	TrustList, Url string
}

// global constants
const VERSION = "1.0-SNAPSHOT"

func main() {
	// start app timer
	appTime := time.Now()
	fmt.Printf("Snatch TLS\n version %s\n\n", VERSION)

	// flag setup
	var (
		trustList = flag.String("trst", "trustList.pem", " the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("url", "https://www.apple.com", "the url used for the connection")
	)
	flag.Parse()
	args := Args{*trustList, *url}

	// Get trust list
	trustedCAs, err := common.GetTrustedCAs(args.TrustList)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = trustedCAs

	// ciphers
	tlsConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.SessionTicketsDisabled = false

	// http client config
	tr := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
	}
	client := http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	fmt.Printf("Connecting to %s\n", args.Url)
	// start request timer
	reqTimer := time.Now()
	// get data
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
	var cipher string
	var tlsVersion string
	tlsConnState := resp.TLS
	if tlsConnState == nil {
		err = errors.New("TLS connection failed")
		fmt.Println(err)
		os.Exit(1)
	}

	// translate cipher to readable string
	switch tlsConnState.CipherSuite {
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	}
	// translate version to readable string
	switch tlsConnState.Version {
	case tls.VersionTLS12:
		tlsVersion = "TLSv1.2"
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

	// parse server cert data
	peerCerts := tlsConnState.PeerCertificates
	srvCert := peerCerts[0]
	CN := srvCert.Subject.CommonName
	O := srvCert.Subject.Organization
	C := srvCert.Subject.Country

	// print out data
	fmt.Println("\nResponse time: ", reqTime)
	fmt.Println("HTTP response status: ", resp.Status)
	fmt.Println("HTTP protocol: ", resp.Proto)
	fmt.Println("TLS version: ", tlsVersion)
	fmt.Println("TLS cipher: ", cipher)
	fmt.Println("Server certificate:")
	fmt.Println("Subject:")
	fmt.Printf("CN=%s\n", CN)
	fmt.Printf("O=%s\n", O[0])
	fmt.Printf("C=%s\n", C[0])
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
