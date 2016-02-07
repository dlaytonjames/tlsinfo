package common

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
)

func GetTrustedCAs(filename string) (certPoop *x509.CertPool, err error) {
	// read in trust list
	trustedCerts, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	// load trust list
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(trustedCerts) {
		err = errors.New("Failed to create trusted list of CAs")
		return
	}
	return
}
