package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const TestCert = `-----BEGIN CERTIFICATE-----
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

var testOrg = []string{"Company"}
var testCountry = []string{"US"}
var testDN = DistinguishedName{
	CN: "Company",
	O:  testOrg,
	C:  testCountry,
}

type dnTestSet struct {
	input  *x509.Certificate
	output DistinguishedName
}

func TestGetIssuerDN(t *testing.T) {
	testCertPem, _ := pem.Decode([]byte(TestCert))
	testCert, _ := x509.ParseCertificate(testCertPem.Bytes)
	issuerDnTests := []dnTestSet{
		{testCert, testDN},
	}
	for _, test := range issuerDnTests {
		v := GetIssuerDN(test.input)
		if v.CN != test.output.CN {
			t.Errorf("Expected: %s, got: %s", test.output.CN, v.CN)
		}
		if v.O[0] != test.output.O[0] {
			t.Errorf("Expected: %s, got: %s", test.output.O[0], v.O[0])
		}
		if v.C[0] != test.output.C[0] {
			t.Errorf("Expected: %s, got: %s", test.output.C[0], v.C[0])
		}
	}
}

func TestGetSubjectDN(t *testing.T) {
	testCertPem, _ := pem.Decode([]byte(TestCert))
	testCert, _ := x509.ParseCertificate(testCertPem.Bytes)
	subjectDnTests := []dnTestSet{
		{testCert, testDN},
	}
	for _, test := range subjectDnTests {
		v := GetSubjectDN(test.input)
		if v.CN != test.output.CN {
			t.Errorf("Expected: %s, got: %s", test.output.CN, v.CN)
		}
		if v.O[0] != test.output.O[0] {
			t.Errorf("Expected: %s, got: %s", test.output.O[0], v.O[0])
		}
		if v.C[0] != test.output.C[0] {
			t.Errorf("Expected: %s, got: %s", test.output.C[0], v.C[0])
		}
	}
}
