package net

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

const (
	TIMEOUT = 10 * time.Second
)

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
