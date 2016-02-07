package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type Args struct {
	TrustList, Url string
}

func main() {
	appTime := time.Now()
	fmt.Println("Started...")

	// flag setup
	var (
		trustList = flag.String("trst", "trustList.pem", " the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("url", "https://www.apple.com", "the url used for the connection")
	)
	flag.Parse()
	args := Args{*trustList, *url}
	fmt.Printf("%+v\n", args)

	// read in trust list
	trustedCerts, err := ioutil.ReadFile(args.TrustList)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// load trust list
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(trustedCerts) {
		err = errors.New("Failed to create trusted list of CAs")
		fmt.Println(err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = certPool

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
	client := http.Client{Transport: tr}
	client.Timeout = 5 * time.Second

	// get data
	resp, err := client.Get(args.Url)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// check response
	if resp.StatusCode != 200 {
		fmt.Println(err)
		os.Exit(1)
	}
	var cipher string
	var tlsVersion string
	tlsConnState := resp.TLS

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
	var stapledOcspResponse bool
	ocspResp := tlsConnState.OCSPResponse
	if len(ocspResp) < 0 {
		stapledOcspResponse = false
	} else {
		stapledOcspResponse = true
		// TODO: parse OCSP response
	}

	peerCerts := tlsConnState.PeerCertificates
	for i, cert := range peerCerts {
		i++
		fmt.Printf("Cert %d subject: %s\n", i, cert.Subject)
	}

	fmt.Println("HTTP response status: ", resp.Status)
	fmt.Println("HTTP protocol: ", resp.Proto)
	fmt.Println("TLS version: ", tlsVersion)
	fmt.Println("TLS cipher: ", cipher)
	fmt.Printf("Stapled OCSP response: %v\n", stapledOcspResponse)

	// end timer
	fmt.Println("\nTime since start: ", time.Since(appTime))
}
