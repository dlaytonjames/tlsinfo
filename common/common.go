package common

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"time"
)

// package constants
const (
	TIMEOUT = 5 * time.Second
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

func GetTlsConfig(certPool *x509.CertPool) (tlsConfig *tls.Config) {
	tlsConfig = &tls.Config{
		RootCAs: certPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
	}
	return
}

func GetHttpClient(tlsConfig *tls.Config) (client http.Client) {
	tr := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DisableCompression:    false,
		TLSHandshakeTimeout:   TIMEOUT,
		ResponseHeaderTimeout: TIMEOUT,
	}
	client = http.Client{
		Transport: tr,
		Timeout:   TIMEOUT,
	}
	return
}

// Translate cipher to readable string.
func GetCipherName(rawCipher uint16) (cipher string) {
	switch rawCipher {
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	}
	return
}

// Translate version to readable string.
func GetTlsName(rawVersion uint16) (version string) {
	switch rawVersion {
	case tls.VersionTLS12:
		version = "TLSv1.2"
	}
	return
}
