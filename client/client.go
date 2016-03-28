package client

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spazbite187/keystone"
	"github.com/spazbite187/snatchtls/network"
)

// Arguments contains the TrustList, URL along with a bool Test, indicating
// testing mode.
type Arguments struct {
	TrustList, URL string
	Test           bool
}

// CipherResults contains a map for the Ciphers.
type CipherResults struct {
	Ciphers map[string]bool
}

// TestResult contains a Pass bool to indicate pass/fail, the CipherName and the connection
// information.
type TestResult struct {
	Pass       bool
	CipherName string
	Info       network.ConnInfo
	Paths      keystone.CertPaths
}

// Report contains pointers to the response data needed for displaying the connection
// information to the user.
type Report struct {
	Trust   string
	URL     string
	Ciphers CipherResults
	Results []TestResult
}

// String method using the Stringer interface.
func (results CipherResults) String() string {
	s := fmt.Sprintf("Supported ciphers:\n")
	for name, supported := range results.Ciphers {
		if supported {
			s = s + fmt.Sprintf("  %s\n", name)
		}
	}
	s = s + fmt.Sprintf("Unsupported ciphers:\n")
	for name, supported := range results.Ciphers {
		if !supported {
			s = s + fmt.Sprintf("  %s\n", name)
		}
	}
	return s
}

// DefaultConnection performs a TLS connection using the default TLS configuration ciphers.
func DefaultConnection(args Arguments) {
	if args.TrustList == "" {
		args.TrustList = "(using system trust)"
	}
	result, err := testConnection(args, 0)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	report := Report{
		Trust:   args.TrustList,
		URL:     args.URL,
		Results: []TestResult{result},
	}
	// display the report
	fmt.Printf("\nTrust: %s\n", report.Trust)
	fmt.Printf("  URL: %s\n\n", report.URL)
	fmt.Println("Connection info:")
	fmt.Print(result.Info)
	fmt.Print(result.Paths)
}

// TestConnections performs TLS connections using TLS configurations with all available ciphers.
func TestConnections(args Arguments) {
	fmt.Println("\nTesting connection...")
	fmt.Println()
	var results = CipherResults{}
	results.Ciphers = make(map[string]bool)
	resultChan := make(chan TestResult)
	for _, cipher := range network.CipherMap {
		go func(cipher interface{}) {
			cipherInt := cipher.(uint16)
			result, _ := testConnection(args, cipherInt)
			resultChan <- result
		}(cipher)
	}

	for i := 0; i < len(network.Ciphers); i++ {
		result := <-resultChan
		results.Ciphers[result.CipherName] = result.Pass
	}
	// print results
	fmt.Print(results)
}

func testConnection(args Arguments, cipher uint16) (TestResult, error) {
	var connInfo network.ConnInfo
	var certPaths keystone.CertPaths
	testResults := TestResult{
		Pass:       false,
		CipherName: network.GetCipherName(cipher),
		Info:       connInfo,
		Paths:      certPaths,
	}
	// get trust list
	trustedCAs := keystone.GetTrustedCAs(args.TrustList)
	// get TLS configuration
	tlsConfig := network.GetTLSConfig(trustedCAs, cipher)
	// get http client
	client := network.GetHTTPClient(tlsConfig)
	// start response timer
	respStartTime := time.Now()
	// perform http GET request
	resp, err := client.Get(args.URL)
	if err != nil {
		return testResults, err
	}
	defer resp.Body.Close()
	// end request timer
	respTime := time.Since(respStartTime)

	// check response
	if resp.StatusCode != 200 {
		err = errors.New("Non 200 status code received")
		return testResults, err
	}
	// check TLS connection
	tlsConnState := resp.TLS
	if tlsConnState == nil {
		err = errors.New("TLS connection failed")
		return testResults, err
	}
	// get cipher name
	cipherName := network.GetCipherName(tlsConnState.CipherSuite)
	// get tls version name
	tlsVersion := network.GetTLSName(tlsConnState.Version)
	// get certs and chains
	peerCerts := tlsConnState.PeerCertificates
	srvCert := peerCerts[0]
	testResults.Paths = tlsConnState.VerifiedChains
	// Check for stapled OCSP response
	var stapledOcspResponse bool
	var ocspInfo keystone.OCSPInfo
	rawOcspResp := tlsConnState.OCSPResponse
	if len(rawOcspResp) > 0 {
		stapledOcspResponse = true
		ocspInfo, err = keystone.GetOCSPInfo(rawOcspResp)
		if err != nil {
			return testResults, err
		}
	}
	// created structs using data obtained from the response
	san := keystone.SubjectAltName{
		DNSName: srvCert.DNSNames,
		IPAddr:  srvCert.IPAddresses,
	}
	serverCert := keystone.CertDetails{
		IssuerDN:  keystone.GetIssuerDN(srvCert),
		SubjectDN: keystone.GetSubjectDN(srvCert),
		SAN:       san,
		Serial:    srvCert.SerialNumber,
	}
	connInfo = network.ConnInfo{
		ResponseTime: respTime,
		Status:       resp.Status,
		Proto:        resp.Proto,
		TLSVersion:   tlsVersion,
		Cipher:       cipherName,
		SrvCert:      serverCert,
		StapledOCSP:  stapledOcspResponse,
		OCSPResp:     ocspInfo,
	}
	testResults.Pass = true
	testResults.Info = connInfo
	return testResults, nil
}
