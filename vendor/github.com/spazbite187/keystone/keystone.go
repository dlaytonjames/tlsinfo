// Package keystone contains common functions for various PKI use cases.
package keystone

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// DistinguishedName contains a subset of a certificate's distinguished name.
// Need to ensure DNs will multiple subvalues are supported, example, multiple Os
type DistinguishedName struct {
	Email, Serial      string
	UID, CN, L, ST, DC string
	OU, O, C           []string
	Unknown            []UndefinedOID
}

// SubjectAltName contains DNSName and IPAddr representing the contents of a certificate's
// subject alternative name.
type SubjectAltName struct {
	DNSName []string
	IPAddr  []net.IP
}

// CertPaths contains a slice containing a slice of x509.Certificates.
type CertPaths [][]*x509.Certificate

// Warning is an type alias for the error type used to represent errors that are not fatal.
type Warning error

// UndefinedOID contains OID and Value string representing an undefined OID.
type UndefinedOID struct {
	OID, Value string
}

// OCSPInfo contains Status, Serial, ThisUpdate and NextUpdate representing a
// subset of OCSP response information.
type OCSPInfo struct {
	Status                 string
	Serial                 *big.Int
	ThisUpdate, NextUpdate time.Time
}

// CertDetails contains SubjectDN, IssuerDN SAN, Serial, NotBefore and NotAfter representing a subset of
// certificate information.
type CertDetails struct {
	SubjectDN, IssuerDN DistinguishedName
	SAN                 SubjectAltName
	Serial              *big.Int
	NotBefore, NotAfter time.Time
}

var (
	// defined OIDs
	cnOID     = asn1.ObjectIdentifier{2, 5, 4, 3}
	serialOID = asn1.ObjectIdentifier{2, 5, 4, 5}
	cOID      = asn1.ObjectIdentifier{2, 5, 4, 6}
	lOID      = asn1.ObjectIdentifier{2, 5, 4, 7}
	stOID     = asn1.ObjectIdentifier{2, 5, 4, 8}
	oOID      = asn1.ObjectIdentifier{2, 5, 4, 10}
	ouOID     = asn1.ObjectIdentifier{2, 5, 4, 11}
	uidOID    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	emailOID  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	dcOID     = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// String function for CertDetails.
func (cert CertDetails) String() string {
	str := fmt.Sprintf("  Serial=%x\n", cert.Serial)
	str = str + fmt.Sprintf("  Subject DN: %s\n", cert.SubjectDN)
	str = str + fmt.Sprintf("  Issuer DN: %s\n", cert.IssuerDN)
	str = str + fmt.Sprintf("  Note Before: %s\n", cert.NotBefore)
	str = str + fmt.Sprintf("  Note After: %s\n", cert.NotAfter)
	str = str + fmt.Sprintf("  Subject Alternative Name (SAN):\n")
	for i, dns := range cert.SAN.DNSName {
		str = str + fmt.Sprintf("	  DNSName[%d]: %s\n", i+1, dns)
	}
	for i, ip := range cert.SAN.IPAddr {
		str = str + fmt.Sprintf("	    IPAddr[%d]: %s\n", i+1, ip)
	}

	return str
}

// String function for OCSPInfo.
func (ocsp OCSPInfo) String() string {
	s := fmt.Sprintf("  Status: %s\n", ocsp.Status)
	// convert serial bigInt to hex
	serialHex := hex.EncodeToString(ocsp.Serial.Bytes())
	s = s + fmt.Sprintf("  Serial: %s\n", serialHex)
	s = s + fmt.Sprintf("  This Update: %s\n", ocsp.ThisUpdate)
	s = s + fmt.Sprintf("  Next Update: %s\n", ocsp.NextUpdate)

	return s
}

// String function for DistinguishedName.
func (dn DistinguishedName) String() string {
	str := ""
	if dn.UID != "" {
		str = fmt.Sprintf("UID=%s, ", dn.UID)
	}
	if dn.Email != "" {
		str = str + fmt.Sprintf("Email=%s, ", dn.Email)
	}
	if dn.Serial != "" {
		str = str + fmt.Sprintf("Serial=%s, ", dn.Serial)
	}
	if dn.CN != "" {
		str = str + fmt.Sprintf("CN=%s, ", dn.CN)
	}
	for _, OU := range dn.OU {
		if OU != "" {
			str = str + fmt.Sprintf("OU=%s, ", OU)
		}
	}
	for _, O := range dn.O {
		if O != "" {
			str = str + fmt.Sprintf("O=%s, ", O)
		}
	}
	if dn.L != "" {
		str = str + fmt.Sprintf("L=%s, ", dn.L)
	}
	if dn.ST != "" {
		str = str + fmt.Sprintf("ST=%s, ", dn.ST)
	}
	for _, C := range dn.C {
		if C != "" {
			str = str + fmt.Sprintf("C=%s, ", C)
		}
	}
	if dn.DC != "" {
		str = str + fmt.Sprintf("DC=%s, ", dn.DC)
	}

	for _, Unknown := range dn.Unknown {
		if Unknown.Value != "" {
			str = str + fmt.Sprintf("%s=%s, ", Unknown.OID, Unknown.Value)
		}
	}

	finalStr := str[:len(str)-2] // remove the trailing ', ' characters from the string
	return finalStr
}

// String function for CertPaths.
func (certPaths CertPaths) String() string {
	str := fmt.Sprintf("Valid paths:\n")
	for pathNum, chain := range certPaths {
		str = str + fmt.Sprintf(" path: %d\n", pathNum+1)
		// reverse chain order
		for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
			chain[i], chain[j] = chain[j], chain[i]
		}
		for cntr, cert := range chain {
			str = str + fmt.Sprintf("  certificate %d: ", cntr+1)
			subject := GetSubjectDN(cert)
			serial := cert.SerialNumber
			str = str + fmt.Sprintf("%s (serial=%x)\n", subject, serial)
		}
	}

	return str
}

// GetSubjectDN is used to parse a x509.Certificate and return a DistinguishedName struct
// containing the certificate's subject distinguished name.
func GetSubjectDN(cert *x509.Certificate) DistinguishedName {
	dn := getDN(cert.Subject)
	return dn
}

// GetIssuerDN is used to parse a x509.Certificate and return a DistinguishedName struct
// containing the certificate's issuer distinguished name.
func GetIssuerDN(cert *x509.Certificate) DistinguishedName {
	dn := getDN(cert.Issuer)
	return dn
}

func getDN(name pkix.Name) DistinguishedName {
	var dn DistinguishedName
	for _, data := range name.Names {
		if data.Type.Equal(uidOID) {
			dn.UID = fmt.Sprintf("%s", data.Value)
		} else if data.Type.Equal(emailOID) {
			dn.Email = fmt.Sprintf("%s", data.Value)
		} else if data.Type.Equal(serialOID) {
			dn.Serial = fmt.Sprintf("%s", data.Value)
		} else if data.Type.Equal(cnOID) {
			dn.CN = fmt.Sprintf("%s", data.Value)
		} else if data.Type.Equal(ouOID) {
			dn.OU = append(dn.OU, fmt.Sprintf("%s", data.Value))
		} else if data.Type.Equal(oOID) {
			dn.O = append(dn.O, fmt.Sprintf("%s", data.Value))
		} else if data.Type.Equal(lOID) {
			dn.L = fmt.Sprintf("%s", data.Value)
		} else if data.Type.Equal(stOID) {
			dn.ST = fmt.Sprintf("%s", data.Value)
		} else if data.Type.Equal(cOID) {
			dn.C = append(dn.C, fmt.Sprintf("%s", data.Value))
		} else if data.Type.Equal(dcOID) {
			dn.DC = fmt.Sprintf("%s", data.Value)
		} else {
			unknownOID := UndefinedOID{
				OID:   fmt.Sprintf("%s", data.Type),
				Value: fmt.Sprintf("%s", data.Value),
			}
			dn.Unknown = append(dn.Unknown, unknownOID)
		}
	}

	return dn
}

// GetTrustedCAs returns a certificate pool of trusted CA certificates or an error
// if an error occurs adding CA certificates to the pool.
func GetTrustedCAs(filename string) *x509.CertPool {
	certPool := x509.NewCertPool()
	// read in trust list
	trustedCerts, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}
	// load trust list
	if !certPool.AppendCertsFromPEM(trustedCerts) {
		return nil
	}
	return certPool
}

// GetCert returns a pointer to an x509 certificate and a nil error unless an error
// is encountered.
func GetCert(input []byte) (*x509.Certificate, error) {
	var cert *x509.Certificate
	if len(input) == 0 {
		err := errors.New("input empty")
		return cert, err
	}
	certPEM, _ := pem.Decode(input)
	if certPEM == nil {
		err := errors.New("error parsing certificate")
		return cert, err
	}
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return cert, err
	}
	return cert, nil
}

func getCertPool(certs []string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certBytes := []byte(cert)
		if !certPool.AppendCertsFromPEM(certBytes) {
			err := errors.New("Failed appending certs to trust list")
			return nil, err
		}
	}
	return certPool, nil
}

// GetCRL is used to retrieve a CRL from specified URL returning the CRL as a slice of bytes.
// The url is a string defining the CRL location. If an error is encountered a non-nil error
// is returned.
func GetCRL(url string) ([]byte, error) {
	var crl []byte
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return crl, err
	}
	// set headers and get http client
	req.Header.Set("Content-Type", "application/pkix-crl")
	client := &http.Client{}
	// send CRL request
	resp, err := client.Do(req)
	if err != nil {
		return crl, err
	}
	defer resp.Body.Close()
	// read body of response
	crl, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return crl, err
	}

	return crl, err
}

// CheckRevoked is used to determine if a certificate specified by serial number has been
// revoked. Serial number of the target certificate and a pointer to a pkix.CertificateList
// are required inputs. An error is return if the serial number is on the CRL.
func CheckRevoked(serial *big.Int, crl *pkix.CertificateList) error {
	var err error
	serialBytes := serial.Bytes()
	// check if target cert serial number is on the revokedCerts list
	revokedCerts := crl.TBSCertList.RevokedCertificates
	for _, revoked := range revokedCerts {
		rvkSerialBytes := revoked.SerialNumber.Bytes()
		if bytes.Equal(serialBytes, rvkSerialBytes) {
			errDetails := fmt.Sprintf("certificate is revoked")
			err = errors.New(errDetails)
			return err
		}
	}

	return err
}

func crlRevCheck(certChain []*x509.Certificate) (Warning, error) {
	var warn Warning
	var warnDetails string
	var passedChecks int
	numChecks := len(certChain) - 1 // revocation can't be checked on the root
	// main revocation check loop
	for i := 0; i < numChecks; i++ {
		target := certChain[i]
		issuer := certChain[i+1]
		// get CRL URLs
		urls := target.CRLDistributionPoints
		numURLs := len(urls)
		var triedURLs int
		// url check loop
		for cntr := 0; triedURLs == 0 && cntr < numURLs; cntr++ {
			url := urls[cntr]
			// get CRL
			crl, err := GetCRL(url)
			if err != nil {
				warnDetails = warnDetails + fmt.Sprintf("\n * Failed to get CRL, details: %s", err)
				warn = errors.New(warnDetails)
				break
			}
			// parse CRL
			revCertList, err := x509.ParseCRL(crl)
			if err != nil {
				warnDetails = warnDetails + fmt.Sprintf("\n * Failed to parse CRL, issuer: %s", GetSubjectDN(issuer))
				warn = errors.New(warnDetails)
				break
			}
			// check CRL validity
			if revCertList.HasExpired(time.Now()) {
				warnDetails = warnDetails + fmt.Sprintf("\n * CRL expired, issuer: %s", GetSubjectDN(issuer))
				warn = errors.New(warnDetails)
				break
			}
			// validate CRL signature
			err = issuer.CheckCRLSignature(revCertList)
			if err != nil {
				warnDetails = warnDetails + fmt.Sprintf("\n * CRL signature invalid, issuer: %s", GetSubjectDN(issuer))
				warn = errors.New(warnDetails)
				break
			}
			// check if the cert has been revoked
			err = CheckRevoked(target.SerialNumber, revCertList)
			if err != nil {
				warn = errors.New(warnDetails)
				return warn, err
			}
			triedURLs++
			passedChecks++
		}
	}

	if warn != nil {
		warn = errors.New(warnDetails)
		return warn, nil
	}

	return nil, nil
}

// GetOCSPInfo is used to get OCSP response details from []byte containing the response. The
// OCSP bytes input needs to be a DER encoded OCSP response. An OCSPInfo struct is returned
// unless an error is encountered and then a non-nil error is returned.
func GetOCSPInfo(ocspBytes []byte) (OCSPInfo, error) {
	// TODO: Add issuer so the signature is validated
	ocspInfo := new(OCSPInfo)
	ocspResp, err := ocsp.ParseResponse(ocspBytes, nil)
	if err != nil {
		return *ocspInfo, err
	}

	ocspInfo.Serial = ocspResp.SerialNumber
	ocspInfo.ThisUpdate = ocspResp.ThisUpdate
	ocspInfo.NextUpdate = ocspResp.NextUpdate
	switch ocspResp.Status {
	case ocsp.Good:
		ocspInfo.Status = "Good"
	case ocsp.Revoked:
		ocspInfo.Status = "Revoked"
	case ocsp.Unknown:
		ocspInfo.Status = "Unknown"
	}

	return *ocspInfo, err
}
