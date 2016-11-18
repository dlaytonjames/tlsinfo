// Package tlsinfo ...
package tlsinfo

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spazbite187/keystone"
)

// Arguments contains the TrustList, URL along with a bool Test, indicating
// testing mode.
type Arguments struct {
	TrustList, URL, Cert string
	Test                 bool
}

// CipherResults contains a map for the Ciphers.
type CipherResults struct {
	Ciphers map[string]bool
}

// TestResult contains a Pass bool to indicate pass/fail, the CipherName and the connection
// information.
type TestResult struct {
	Pass       bool
	Timestamp  time.Time
	CipherName string // TODO: may be redundent
	Info       ConnInfo
	Paths      keystone.CertPaths
	Chains     [][]*x509.Certificate
	Cert       *x509.Certificate
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
	result, err := TestConnection(args, 0)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if args.Cert != "" {
		file, err := os.Create(args.Cert)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		w := bufio.NewWriter(file)
		_, err = w.Write(result.Cert.Raw)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		w.Flush()
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
	for _, cipher := range CipherMap {
		go func(cipher interface{}) {
			cipherInt := cipher.(uint16)
			result, _ := TestConnection(args, cipherInt)
			resultChan <- result
		}(cipher)
	}

	for i := 0; i < len(Ciphers); i++ {
		result := <-resultChan
		results.Ciphers[result.CipherName] = result.Pass
	}
	// print results
	fmt.Print(results)
}

// TestConnection performs a TLS connection using the supplied cipher.
func TestConnection(args Arguments, cipher uint16) (TestResult, error) {
	var connInfo ConnInfo
	var certPaths keystone.CertPaths
	testResults := TestResult{
		Pass:       false,
		Timestamp:  time.Now(),
		CipherName: GetCipherName(cipher),
		Info:       connInfo,
		Paths:      certPaths,
	}
	trustedCAs := keystone.GetTrustedCAs(args.TrustList) // get trust list
	tlsConfig := GetTLSConfig(trustedCAs, cipher)        // get TLS configuration
	client := GetHTTPClient(tlsConfig)                   // get http client
	respStartTime := time.Now()                          // start response timer

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
		testResults.Cert = tlsConnState.PeerCertificates[0]
		err = errors.New("TLS connection failed")
		return testResults, err
	}
	// get cipher name
	cipherName := GetCipherName(tlsConnState.CipherSuite)
	// get tls version name
	tlsVersion := GetTLSName(tlsConnState.Version)
	// get certs and chains
	srvCert := tlsConnState.PeerCertificates[0]
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
		NotBefore: srvCert.NotBefore,
		NotAfter:  srvCert.NotAfter,
	}
	connInfo = ConnInfo{
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
	testResults.CipherName = cipherName
	testResults.Info = connInfo
	testResults.Cert = srvCert
	testResults.Chains = tlsConnState.VerifiedChains

	return testResults, nil
}

func saveCert(file string, cert x509.Certificate) error {

	return nil
}
