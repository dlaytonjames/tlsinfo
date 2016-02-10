package certs

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
)

type Cert struct {
	SubjectDN, IssuerDN DistinguishedName
	SAN                 SubjectAltName
}

func (cert Cert) String() string {
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

	//for i, dnsName := range sanDns {
	//	i++
	//	fmt.Printf("	DNSName[%d]: %s\n", i, dnsName)
	//}
	//sanIPs := srvCert.IPAddresses
	//for i, ip := range sanIPs {
	//	i++
	//	fmt.Printf("	IPAddress[%d]: %v\n", i, ip)
	//}

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
