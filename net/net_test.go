package net

import (
	"crypto/tls"
	"testing"
)

type cipherTestSet struct {
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

func TestGetCipherName(t *testing.T) {
	for _, test := range cipherTests {
		v := GetCipherName(test.input)
		if v != test.output {
			t.Errorf("Expected: %s, got: ", test.output, v)
		}
	}
}

type tlsNameTestSet struct {
	input  uint16
	output string
}

var tlsNameTests = []tlsNameTestSet{
	{tls.VersionTLS12, "TLSv1.2"},
	{0, "unknown"},
}

func TestGetTlsName(t *testing.T) {
	for _, test := range tlsNameTests {
		v := GetTlsName(test.input)
		if v != test.output {
			t.Errorf("Expected: %s, got: ", test.output, v)
		}
	}
}
