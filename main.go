package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/spazbite187/snatchtls/Godeps/_workspace/src/golang.org/x/crypto/ocsp"
	"github.com/spazbite187/snatchtls/net"
	"github.com/spazbite187/snatchtls/pki"
)

type Args struct {
	TrustList, Url string
}

// package constants
const (
	VERSION = "1.0.0-SNAPSHOT"
)

func main() {
	// start app timer
	appTime := time.Now()

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
	)
	flag.Parse()
	args := Args{*trustList, *url}

	// print out intro and args
	fmt.Printf("Snatch TLS\n version %s\n\n", VERSION)

	// Get trust list
	trustedCAs, err := pki.GetTrustedCAs(args.TrustList)
	if err != nil {
		args.TrustList = "(using system trust)"
	}

	// Get TLS configuration
	tlsConfig := net.GetTlsConfig(trustedCAs)

	// Get http client
	client := net.GetHttpClient(tlsConfig)

	// start response timer
	respStartTime := time.Now()
	// perform http GET request
	resp, err := client.Get(args.Url)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	// end request timer
	respTime := time.Since(respStartTime)

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

	// get cipher name
	cipher := net.GetCipherName(tlsConnState.CipherSuite)
	// get tls version name
	tlsVersion := net.GetTlsName(tlsConnState.Version)
	// Check for stapled OCSP response
	var status string
	var serialNum *big.Int
	var thisUpdate time.Time
	var nextUpdate time.Time
	var stapledOcspResponse bool
	rawOcspResp := tlsConnState.OCSPResponse
	if len(rawOcspResp) > 0 {
		stapledOcspResponse = true
		ocspResp, err := ocsp.ParseResponse(rawOcspResp, nil)
		if err != nil {
			fmt.Println(err)
		} else {
			serialNum = ocspResp.SerialNumber
			thisUpdate = ocspResp.ThisUpdate
			nextUpdate = ocspResp.NextUpdate
			switch ocspResp.Status {
			case ocsp.Good:
				status = "Good"
			case ocsp.Revoked:
				status = "Revoked"
			case ocsp.Unknown:
				status = "Unknown"
			}
		}
	}
	// get server cert subject name
	peerCerts := tlsConnState.PeerCertificates
	srvCert := peerCerts[0]
	san := pki.SubjectAltName{
		DNSName: srvCert.DNSNames,
		IPAddr:  srvCert.IPAddresses,
	}
	serverCert := pki.CertInfo{
		IssuerDN:  pki.GetIssuerDN(srvCert),
		SubjectDN: pki.GetSubjectDN(srvCert),
		SAN:       san,
	}
	ocspInfo := pki.OcspInfo{
		Status:     status,
		Serial:     serialNum,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	connInfo := net.ConnInfo{
		ResponseTime: respTime,
		Status:       resp.Status,
		Proto:        resp.Proto,
		TlsVersion:   tlsVersion,
		Cipher:       cipher,
		SrvCert:      serverCert,
		StapledOCSP:  stapledOcspResponse,
	}

	// print out data
	fmt.Printf("Trust list: %s\n", args.TrustList)
	fmt.Printf("       URL: %s\n\n", args.Url)
	fmt.Println("Connection info:")
	fmt.Println(connInfo)
	fmt.Println("Server certificate:")
	fmt.Println(serverCert)
	if connInfo.StapledOCSP {
		fmt.Println("\nOCSP response details:")
		fmt.Println(ocspInfo)
	}

	// end app timer
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
