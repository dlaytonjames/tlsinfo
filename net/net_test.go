package net

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

type clientTestSet struct {
	input  *tls.Config
	output http.Client
}

type cipherTestSet struct {
	input  uint16
	output string
}

type tlsNameTestSet struct {
	input  uint16
	output string
}

var cipherTests = []cipherTestSet{
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
	{0, "unknown"},
}

var tlsNameTests = []tlsNameTestSet{
	{tls.VersionTLS12, "TLSv1.2"},
	{0, "unknown"},
}

func TestGetHttpClient(t *testing.T) {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(TEST_CERT))
	tlsConfig := GetTlsConfig(certPool)
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
	clientTests := []clientTestSet{
		{tlsConfig, client},
	}
	for _, test := range clientTests {
		v := GetHttpClient(tlsConfig)
		if v.Timeout != test.output.Timeout {
			t.Errorf("Expected: %s, got: ", test.output.Timeout, v.Timeout)
		}
	}
}

func TestGetCipherName(t *testing.T) {
	for _, test := range cipherTests {
		v := GetCipherName(test.input)
		if v != test.output {
			t.Errorf("Expected: %s, got: ", test.output, v)
		}
	}
}

func TestGetTlsName(t *testing.T) {
	for _, test := range tlsNameTests {
		v := GetTlsName(test.input)
		if v != test.output {
			t.Errorf("Expected: %s, got: ", test.output, v)
		}
	}
}

const (
	TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIC+DCCAeACCQD6yTQ6qQbuNjANBgkqhkiG9w0BAQUFADA+MQswCQYDVQQGEwJV
UzELMAkGA1UECBMCQ0ExEDAOBgNVBAoTB0NvbXBhbnkxEDAOBgNVBAMTB0NvbXBh
bnkwHhcNMTYwMjExMDcwODUwWhcNMjYwMjA4MDcwODUwWjA+MQswCQYDVQQGEwJV
UzELMAkGA1UECBMCQ0ExEDAOBgNVBAoTB0NvbXBhbnkxEDAOBgNVBAMTB0NvbXBh
bnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDemgoeEl7B+B7v+mE3
zYYHckHJyHWniQeubebjQGOJazB5FF0jTbPW4ipyleozNzOjHah54b7gPFTriu4P
50of3tNfVG5/E1NNAFJ+3cRK/xDM/X4b8ofYsQ0eQVJHEm5cc0aOW/CVaMAWSzwm
sAr5gZ6nfa6EO1Dm42ODlxvVRiwi6+MW/3QQkPdFDSz8WbcqFMH/aj1PD8m3gVGE
mUFL3kui3r+7KR+gT8fhy5Oev3nOYm1lVVFh3S2/Yw7MBFul15dC40+O68kXTwW9
wTJh2QOjlIOplqeqF/4I0m8NU6ik9PF+y1nGQLevLGWmYNKNUdsDhLbi5cExgB/Z
HCC3AgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAFR2K3Z0UDKe9KI6hamjHDjS7fAk
8f9LJTjPDqo75iW4mvJUMI/kqDx7+5N/0fw9qwmWu6giC4VvNQl1YfWaRNQKw6zK
bbfjEbSfW7XXA6r/f8DyjlEVMIK+JIILcP6yB/7hoDV0RXmJfp/BTYKQqvdS2z7y
bDp3F0KbyRW9LJ7F+6pHwEZuSSuZxA6K/ZQ5eWzP2/lmAlmH9mJ4ZcOEw5b7btWb
U0sWyvLO550nKzwvAJI7LhX40AWa3pppOO/eXyw01pzK5jV9lNk/5MukHfzaSYpm
NyXHkKoRNr09pq8yqlyZoGalzc5Xlr3HpG9GYjttoS7+hFgcP5JZkWX/9yU=
-----END CERTIFICATE-----`
)
