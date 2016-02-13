package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

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
	fmt.Printf("Snatch TLS\n version %s\n\n", VERSION)

	// flag setup
	var (
		trustList = flag.String("t", "", "the filename for the trusted CAs (PEM encoded)")
		url       = flag.String("u", "https://www.google.com", "the url used for the connection")
	)
	flag.Parse()
	args := Args{*trustList, *url}

	// Get connection client struct
	connClient := net.GetConnClient(args.TrustList)
	trust := connClient.TlsConfig.RootCAs
	if trust == nil {
		args.TrustList = "(using system trust)"
	}
	client := connClient.HttpClient
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
	var stapledOcspResponse bool
	var ocspInfo pki.OcspInfo
	rawOcspResp := tlsConnState.OCSPResponse
	if len(rawOcspResp) > 0 {
		stapledOcspResponse = true
		ocspInfo, err = pki.GetOcspInfo(rawOcspResp)
		if err != nil {
			fmt.Println(err)
		}
	}
	// created structs using data obtained from the response
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
	fmt.Print(serverCert)
	if connInfo.StapledOCSP {
		fmt.Println("\nOCSP response details:")
		fmt.Print(ocspInfo)
	}
	// end app timer and print out total time
	fmt.Println("\nTotal app time: ", time.Since(appTime))
}
