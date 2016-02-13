package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spazbite187/snatchtls/net"
	"github.com/spazbite187/snatchtls/pki"
)

// TestResults contains a map for the CipherResults.
type TestResults struct {
	CipherResults map[string]bool
}

type testResult struct {
	Details string
	Pass    bool
}

// DefaultConnection performs a TLS connection using the default TLS configuration ciphers.
func DefaultConnection(args arguments) {
	// Get connection client
	connClient := net.GetConnClient(args.TrustList, 0)
	client := connClient.HTTPClient
	trust := connClient.TLSConfig.RootCAs
	if trust == nil {
		args.TrustList = "(using system trust)"
	}
	// start response timer
	respStartTime := time.Now()
	// perform http GET request
	resp, err := client.Get(args.URL)
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
	tlsVersion := net.GetTLSName(tlsConnState.Version)
	// Check for stapled OCSP response
	var stapledOcspResponse bool
	var ocspInfo pki.OCSPInfo
	rawOcspResp := tlsConnState.OCSPResponse
	if len(rawOcspResp) > 0 {
		stapledOcspResponse = true
		ocspInfo, err = pki.GetOCSPInfo(rawOcspResp)
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
		TLSVersion:   tlsVersion,
		Cipher:       cipher,
		SrvCert:      serverCert,
		StapledOCSP:  stapledOcspResponse,
	}

	// print out data
	fmt.Printf("\nTrust list: %s\n", args.TrustList)
	fmt.Printf("       URL: %s\n\n", args.URL)
	fmt.Println("Connection info:")
	fmt.Println(connInfo)
	fmt.Println("Server certificate:")
	fmt.Print(serverCert)
	if connInfo.StapledOCSP {
		fmt.Println("\nOCSP response details:")
		fmt.Print(ocspInfo)
	}
}

// TestConnections performs TLS connections using TLS configurations with all available ciphers.
func TestConnections(args arguments) {
	fmt.Println("Runing tests...")
	var testResults = TestResults{}
	testResults.CipherResults = make(map[string]bool)
	for key, cipher := range net.CipherMap {
		_, err := testConnection(args, cipher)
		if err != nil {
			testResults.CipherResults[key] = false
		}
		testResults.CipherResults[key] = true
	}
	fmt.Println("Results:")
	fmt.Printf("%v\n", testResults)
}

func testConnection(args arguments, cipher uint16) (testResult, error) {
	testResult := testResult{}
	// Get connection client
	connClient := net.GetConnClient(args.TrustList, cipher)
	client := connClient.HTTPClient
	trust := connClient.TLSConfig.RootCAs
	if trust == nil {
		args.TrustList = "(using system trust)"
	}
	// start response timer
	respStartTime := time.Now()
	// perform http GET request
	resp, err := client.Get(args.URL)
	if err != nil {
		testResult.Pass = false
		return testResult, err
	}
	defer resp.Body.Close()
	// end request timer
	respTime := time.Since(respStartTime)

	// check response
	if resp.StatusCode != 200 {
		testResult.Pass = false
		return testResult, err
	}
	// check TLS connection
	tlsConnState := resp.TLS
	if tlsConnState == nil {
		err = errors.New("TLS connection failed")
		testResult.Pass = false
		return testResult, err
	}

	// get cipher name
	cipherName := net.GetCipherName(tlsConnState.CipherSuite)
	// get tls version name
	tlsVersion := net.GetTLSName(tlsConnState.Version)
	// Check for stapled OCSP response
	var stapledOcspResponse bool
	rawOcspResp := tlsConnState.OCSPResponse
	if len(rawOcspResp) > 0 {
		stapledOcspResponse = true
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
		TLSVersion:   tlsVersion,
		Cipher:       cipherName,
		SrvCert:      serverCert,
		StapledOCSP:  stapledOcspResponse,
	}

	testResult.Details = fmt.Sprintf("Connection info:\n%s", connInfo)
	testResult.Pass = true
	return testResult, err
}
