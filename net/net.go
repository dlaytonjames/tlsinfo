package net

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/spazbite187/snatchtls/pki"
)

const (
	TIMEOUT = 10 * time.Second
)

type ConnInfo struct {
	ResponseTime                      time.Duration
	Status, Proto, TlsVersion, Cipher string
	SrvCert                           pki.CertInfo
	StapledOCSP                       bool
}

func (connInfo ConnInfo) String() string {
	s := fmt.Sprintf("  Response time: %s\n", connInfo.ResponseTime)
	s = s + fmt.Sprintf("  HTTP response status: %s\n", connInfo.Status)
	s = s + fmt.Sprintf("  HTTP protocol: %s\n", connInfo.Proto)
	s = s + fmt.Sprintf("  TLS version: %s\n", connInfo.TlsVersion)
	s = s + fmt.Sprintf("  TLS cipher: %s\n", connInfo.Cipher)
	s = s + fmt.Sprintf("  Stapled OCSP response: %v\n", connInfo.StapledOCSP)

	return s
}

// Get configured HTTP client struct.
func GetHttpClient(tlsConfig *tls.Config) http.Client {
	tr := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DisableCompression:    false,
		TLSHandshakeTimeout:   TIMEOUT,
		ResponseHeaderTimeout: TIMEOUT,
	}
	client := http.Client{
		Transport: tr,
		Timeout:   TIMEOUT,
	}
	return client
}

// Get configured TLS struct.
func GetTlsConfig(certPool *x509.CertPool) *tls.Config {
	tlsConfig := &tls.Config{
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
	return tlsConfig
}

// Translate cipher to readable string.
func GetCipherName(rawCipher uint16) string {
	var cipher string
	switch rawCipher {
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	default:
		cipher = "unknown"
	}
	return cipher
}

// Translate version to readable string.
func GetTlsName(rawVersion uint16) string {
	var version string
	switch rawVersion {
	case tls.VersionTLS12:
		version = "TLSv1.2"
	default:
		version = "unknown"
	}
	return version
}
