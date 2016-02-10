package certs

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
)

type CertSubjectDN struct {
	CN, OU, O, C string
}

func GetSubjectDn(cert *x509.Certificate) (certSubDN CertSubjectDN) {
	// TODO: leverage OU, O, and C lists
	certSubDN.CN = cert.Subject.CommonName
	listO := cert.Subject.Organization
	certSubDN.O = listO[0]
	listC := cert.Subject.Country
	certSubDN.C = listC[0]
	return
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
