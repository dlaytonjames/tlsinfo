package net

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/spazbite187/snatchtls/pki"
)

// ConnClient contains TlsConfig and HttpClient used for TLS connections.
type ConnClient struct {
	TLSConfig  *tls.Config
	HTTPClient http.Client
}

// ConnInfo contains detailed information from a successful TLS connection.
type ConnInfo struct {
	ResponseTime                      time.Duration
	Status, Proto, TLSVersion, Cipher string
	SrvCert                           pki.CertInfo
	StapledOCSP                       bool
}

func (connInfo ConnInfo) String() string {
	s := fmt.Sprintf("  Response time: %s\n", connInfo.ResponseTime)
	s = s + fmt.Sprintf("  HTTP response status: %s\n", connInfo.Status)
	s = s + fmt.Sprintf("  HTTP protocol: %s\n", connInfo.Proto)
	s = s + fmt.Sprintf("  TLS version: %s\n", connInfo.TLSVersion)
	s = s + fmt.Sprintf("  TLS cipher: %s\n", connInfo.Cipher)
	s = s + fmt.Sprintf("  Stapled OCSP response: %v\n", connInfo.StapledOCSP)

	return s
}

// Get configured HTTP client struct.
func getHTTPClient(tlsConfig *tls.Config) http.Client {
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
func getTLSConfig(certPool *x509.CertPool, cipher uint16) *tls.Config {
	if cipher == 0 {
		tlsConfig := &tls.Config{
			RootCAs:                certPool,
			CipherSuites:           Ciphers,
			MinVersion:             tls.VersionSSL30,
			SessionTicketsDisabled: false,
		}
		return tlsConfig
	}
	selCipher := []uint16{cipher}
	tlsConfig := &tls.Config{
		RootCAs:                certPool,
		CipherSuites:           selCipher,
		MinVersion:             tls.VersionSSL30,
		SessionTicketsDisabled: false,
	}
	return tlsConfig
}

// GetConnClient gets a connection client containing a configured tls.Config and http.Client
func GetConnClient(trustFile string, cipher uint16) ConnClient {
	connClient := new(ConnClient)
	// Get trust list
	trustedCAs, _ := pki.GetTrustedCAs(trustFile)
	// Get TLS configuration
	connClient.TLSConfig = getTLSConfig(trustedCAs, cipher)
	// Get http client
	connClient.HTTPClient = getHTTPClient(connClient.TLSConfig)
	return *connClient
}

// GetCipherName translates unint16 cipher to readable string.
func GetCipherName(rawCipher uint16) string {
	// TODO: update to use CipherMap
	var cipher string
	switch rawCipher {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		cipher = "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		cipher = "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		cipher = "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		cipher = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		cipher = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		cipher = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		cipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		cipher = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	default:
		cipher = "unknown"
	}
	return cipher
}

// GetTLSName translates unint16 version to readable string.
func GetTLSName(rawVersion uint16) string {
	var version string
	switch rawVersion {
	case tls.VersionSSL30:
		version = "SSLv3.0"
	case tls.VersionTLS10:
		version = "TLSv1.0"
	case tls.VersionTLS11:
		version = "TLSv1.1"
	case tls.VersionTLS12:
		version = "TLSv1.2"
	default:
		version = "unknown"
	}
	return version
}

// TIMEOUT hold the number of seconds for timeout settings.
const TIMEOUT = 10 * time.Second

// Package variables
var (
	Ciphers = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
	CipherMap = map[string]uint16{
		"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
)
