package pki

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"

	"encoding/hex"
	"golang.org/x/crypto/ocsp"
)

// CertInfo contains SubjectDN, IssuerDN and SAN representing a subset of
// certificate information.
type CertInfo struct {
	SubjectDN, IssuerDN DistinguishedName
	SAN                 SubjectAltName
	Serial              *big.Int
}

func (cert CertInfo) String() string {
	serialHex := hex.EncodeToString(cert.Serial.Bytes())
	str := fmt.Sprintf("  Serial=%s\n", serialHex)
	str = str + fmt.Sprintf("  Issuer DN:\n")
	str = str + fmt.Sprintf("      CN=%s\n", cert.IssuerDN.CN)
	for _, OU := range cert.IssuerDN.OU {
		str = str + fmt.Sprintf("       OU=%s\n", OU)
	}
	for _, O := range cert.IssuerDN.O {
		str = str + fmt.Sprintf("       O=%s\n", O)
	}
	for _, C := range cert.IssuerDN.C {
		str = str + fmt.Sprintf("       C=%s\n", C)
	}
	str = str + fmt.Sprintf("  Subject DN:\n")
	str = str + fmt.Sprintf("      CN=%s\n", cert.SubjectDN.CN)
	for _, OU := range cert.SubjectDN.OU {
		str = str + fmt.Sprintf("       OU=%s\n", OU)
	}
	for _, O := range cert.SubjectDN.O {
		str = str + fmt.Sprintf("       O=%s\n", O)
	}
	for _, C := range cert.SubjectDN.C {
		str = str + fmt.Sprintf("       C=%s\n", C)
	}
	str = str + fmt.Sprintf("  Subject Alternative Name (SAN):\n")
	for i, dns := range cert.SAN.DNSName {
		str = str + fmt.Sprintf("	  DNSName[%d]: %s\n", i+1, dns)
	}
	for i, ip := range cert.SAN.IPAddr {
		str = str + fmt.Sprintf("	    IPAddr[%d]: %s\n", i+1, ip)
	}

	return str
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
	// convert serial bigInt to hex
	serialHex := hex.EncodeToString(ocsp.Serial.Bytes())
	s = s + fmt.Sprintf("  Serial: %s\n", serialHex)
	s = s + fmt.Sprintf("  This Update: %s\n", ocsp.ThisUpdate)
	s = s + fmt.Sprintf("  Next Update: %s\n", ocsp.NextUpdate)

	return s
}

// DistinguishedName contains CN, O and C representing a subset of a certificate's
// distinguished name.
type DistinguishedName struct {
	CN       string
	OU, O, C []string
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
		OU: cert.Issuer.OrganizationalUnit,
		O:  cert.Issuer.Organization,
		C:  cert.Issuer.Country,
	}
	return dn
}

// GetSubjectDN returns the certificate's subject distinguished name.
func GetSubjectDN(cert *x509.Certificate) DistinguishedName {
	dn := DistinguishedName{
		CN: cert.Subject.CommonName,
		OU: cert.Issuer.OrganizationalUnit,
		O:  cert.Subject.Organization,
		C:  cert.Subject.Country,
	}
	return dn
}

// GetTrustedCAs returns a certificate pool of trusted CA certificates or an error
// if an error occurs adding CA certificates to the pool.
func GetTrustedCAs(filename string) *x509.CertPool {
	certPool := x509.NewCertPool()
	// read in trust list
	trustedCerts, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}
	// load trust list
	if !certPool.AppendCertsFromPEM(trustedCerts) {
		return nil
	}
	return certPool
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
