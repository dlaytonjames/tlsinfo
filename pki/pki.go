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

type OcspInfo struct {
	Status                 string
	Serial                 *big.Int
	ThisUpdate, NextUpdate time.Time
}

func (ocsp OcspInfo) String() string {
	s := fmt.Sprintf("  Status: %s\n", ocsp.Status)
	s = s + fmt.Sprintf("  Serial: %d\n", ocsp.Serial)
	s = s + fmt.Sprintf("  This Update: %s\n", ocsp.ThisUpdate)
	s = s + fmt.Sprintf("  Next Update: %s\n", ocsp.NextUpdate)

	return s
}

type DistinguishedName struct {
	CN   string
	O, C []string
}

type SubjectAltName struct {
	DNSName []string
	IPAddr  []net.IP
}

// Get the certificate's issuer distinguished name.
func GetIssuerDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Issuer.CommonName,
		O:  cert.Issuer.Organization,
		C:  cert.Issuer.Country,
	}
	return dn
}

// Get the certificate's subject distinguished name.
func GetSubjectDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Subject.CommonName,
		O:  cert.Subject.Organization,
		C:  cert.Subject.Country,
	}
	return dn
}

// Get certificate pool of trusted CA certificates.
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

// Get details from a DER encoded OCSP response.
// TODO: Add issuer so the signature is validated
func GetOcspInfo(ocspBytes []byte) (OcspInfo, error) {
	ocspInfo := new(OcspInfo)
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
