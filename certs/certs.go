package certs

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"
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

func GetIssuerDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Issuer.CommonName,
		O:  cert.Issuer.Organization,
		C:  cert.Issuer.Country,
	}
	return dn
}

func GetSubjectDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Subject.CommonName,
		O:  cert.Subject.Organization,
		C:  cert.Subject.Country,
	}
	return dn
}

func GetTrustedCAs(filename string) (certPool *x509.CertPool, err error) {
	// read in trust list
	trustedCerts, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	// load trust list
	certPool = x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(trustedCerts) {
		err = errors.New("Failed to create trusted list of CAs")
		return
	}
	return
}
