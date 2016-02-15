package client

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spazbite187/snatchtls/net"
	"github.com/spazbite187/snatchtls/pki"
)

// Version contains details about the current version.
const Version = "1.0.0-DEV"

// Arguments contains the TrustList, URL along with a bool Test, indicating
// testing mode.
type Arguments struct {
	TrustList, URL string
	Test           bool
}

// TestResults contains a map for the CipherResults.
type TestResults struct {
	CipherResults map[string]bool
}

// TestResult contains a Pass bool to indicate pass/fail and the CipherName.
type TestResult struct {
	Pass       bool
	CipherName string
}

// String method using the Stringer interface.
func (testResults TestResults) String() string {
	s := fmt.Sprintf("Supported ciphers:\n")
	for name, supported := range testResults.CipherResults {
		if supported {
			s = s + fmt.Sprintf("  %s\n", name)
		}
	}
	s = s + fmt.Sprintf("Unsupported ciphers:\n")
	for name, supported := range testResults.CipherResults {
		if !supported {
			s = s + fmt.Sprintf("  %s\n", name)
		}
	}
	return s
}

// DefaultConnection performs a TLS connection using the default TLS configuration ciphers.
func DefaultConnection(args Arguments) {
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
func TestConnections(args Arguments) {
	fmt.Println("\nTesting connection...")
	fmt.Println()
	var testResults = TestResults{}
	testResults.CipherResults = make(map[string]bool)
	resultChan := make(chan TestResult)
	for _, cipher := range net.CipherMap {
		go func(cipher interface{}) {
			cipherInt := cipher.(uint16)
			resultChan <- testConnection(args, cipherInt)
		}(cipher)
	}

	for i := 0; i < len(net.Ciphers); i++ {
		result := <-resultChan
		testResults.CipherResults[result.CipherName] = result.Pass
	}

	fmt.Print(testResults)
}

func testConnection(args Arguments, cipher uint16) TestResult {
	testResults := TestResult{
		Pass:       false,
		CipherName: net.GetCipherName(cipher),
	}
	// Get connection client
	connClient := net.GetConnClient(args.TrustList, cipher)
	client := connClient.HTTPClient
	// perform http GET request
	resp, err := client.Get(args.URL)
	if err != nil {
		return testResults
	}
	defer resp.Body.Close()

	// check response
	if resp.StatusCode != 200 {
		return testResults
	}
	// check TLS connection
	tlsConnState := resp.TLS
	if tlsConnState == nil {
		return testResults
	}
	testResults.Pass = true
	return testResults
}
