package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CertInfo contains SubjectDN, IssuerDN and SAN representing a subset of
// certificate information.
type CertInfo struct {
	SubjectDN, IssuerDN DistinguishedName
	SAN                 SubjectAltName
}

func (cert CertInfo) String() string {
	s := fmt.Sprintf("  Issuer DN:\n")
	s = s + fmt.Sprintf("      CN=%s\n", cert.IssuerDN.CN)
	s = s + fmt.Sprintf("       O=%s\n", cert.IssuerDN.O)
	s = s + fmt.Sprintf("       C=%s\n", cert.IssuerDN.C)
	s = s + fmt.Sprintf("  Subject DN:\n")
	s = s + fmt.Sprintf("      CN=%s\n", cert.SubjectDN.CN)
	s = s + fmt.Sprintf("       O=%s\n", cert.SubjectDN.O)
	s = s + fmt.Sprintf("       C=%s\n", cert.SubjectDN.C)
	s = s + fmt.Sprintf("  Subject Alternative Name (SAN):\n")
	s = s + fmt.Sprintf("	  DNSNames: %s\n", cert.SAN.DNSName)
	s = s + fmt.Sprintf("	    IPAddr: %s\n", cert.SAN.IPAddr)

	return s
}

// OCSPInfo contains Status, Serial, ThisUpdate and NextUpdate representing a
// subset of OCSP response information.
type OCSPInfo struct {
	Status                 string
	Serial                 *big.Int
	ThisUpdate, NextUpdate time.Time
}

func (ocsp OCSPInfo) String() string {
	s := fmt.Sprintf("  Status: %s\n", ocsp.Status)
	s = s + fmt.Sprintf("  Serial: %d\n", ocsp.Serial)
	s = s + fmt.Sprintf("  This Update: %s\n", ocsp.ThisUpdate)
	s = s + fmt.Sprintf("  Next Update: %s\n", ocsp.NextUpdate)

	return s
}

// DistinguishedName contains CN, O and C representing a subset of a certificate's
// distinguished name.
type DistinguishedName struct {
	CN   string
	O, C []string
}

// SubjectAltName contains DNSName and IPAddr representing the contents of a certificate's
// subject alternative name.
type SubjectAltName struct {
	DNSName []string
	IPAddr  []net.IP
}

// GetIssuerDN returns the certificate's issuer distinguished name.
func GetIssuerDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Issuer.CommonName,
		O:  cert.Issuer.Organization,
		C:  cert.Issuer.Country,
	}
	return dn
}

// GetSubjectDN returns the certificate's subject distinguished name.
func GetSubjectDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Subject.CommonName,
		O:  cert.Subject.Organization,
		C:  cert.Subject.Country,
	}
	return dn
}

// GetTrustedCAs returns a certificate pool of trusted CA certificates or an error
// if an error occurs adding CA certificates to the pool.
func GetTrustedCAs(filename string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	// read in trust list
	trustedCerts, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	// load trust list
	if !certPool.AppendCertsFromPEM(trustedCerts) {
		err = errors.New("Failed to create trusted list of CAs")
		return nil, err
	}
	return certPool, err
}

// GetOCSPInfo returns OCSPInfo containing details from a DER encoded OCSP response or
// an error if an error occurs parsing the OCSP response.
func GetOCSPInfo(ocspBytes []byte) (OCSPInfo, error) {
	// TODO: Add issuer so the signature is validated
	ocspInfo := new(OCSPInfo)
	ocspResp, err := ocsp.ParseResponse(ocspBytes, nil)
	if err != nil {
		return *ocspInfo, err
	}

	ocspInfo.Serial = ocspResp.SerialNumber
	ocspInfo.ThisUpdate = ocspResp.ThisUpdate
	ocspInfo.NextUpdate = ocspResp.NextUpdate
	switch ocspResp.Status {
	case ocsp.Good:
		ocspInfo.Status = "Good"
	case ocsp.Revoked:
		ocspInfo.Status = "Revoked"
	case ocsp.Unknown:
		ocspInfo.Status = "Unknown"
	}
	return *ocspInfo, err
}
