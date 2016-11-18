## TLS Info (tlsinfo)

tlsinfo is a command line tool for getting the connection details of a TLS end point. In test mode it will
return a list of allowed TLS ciphers.

## Install
```console
$ go get -u github.com/spazbite187/tlsinfo
```
## Usage
Running `tlsinfo` without any arguments will use the system trust store for server certificate validation and
`https://www.google.com` as the URL.
```console
$ tlsinfo
TLS Info
  version 1.0.0-DEV

Trust: (using system trust)
  URL: https://www.google.com

Connection info:
  Response time: 178.996735ms
  HTTP response status: 200 OK
  HTTP protocol: HTTP/2.0
  TLS version: TLSv1.2
  TLS cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  Stapled OCSP response: false
Server certificate:
  Serial=5a0561c8993222b4
  Subject DN: CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US
  Issuer DN: CN=Google Internet Authority G2, O=Google Inc, C=US
  Note Before: 2016-07-28 11:40:00 +0000 UTC
  Note After: 2016-10-20 11:40:00 +0000 UTC
  Subject Alternative Name (SAN):
	  DNSName[1]: www.google.com

Total app time:  116.279735ms
```
To run with a specific URL, use the `-u` flag to specify the TLS endpoint.
```console
$ tlsinfo -u https://www.apple.com
...
```
To run with a custom trust store, use the `-t` flag to specify the file containing a list of PEM encoded
CA certificates.
```console
$ tlsinfo -t trustList.pem
...
```
To run in test mode, use the `-test=true` flag. Test mode will attempt to connect using all the configure
TLS ciphers and report on the results.
```console
$ tlsinfo -test=true
TLS Info
  version 1.0.0-DEV

Trust: (using system trust)
  URL: https://www.google.com

Connection info:
  Response time: 176.700378ms
  HTTP response status: 200 OK
  HTTP protocol: HTTP/2.0
  TLS version: TLSv1.2
  TLS cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  Stapled OCSP response: false
Server certificate:
  Serial=5a0561c8993222b4
  Subject DN: CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US
  Issuer DN: CN=Google Internet Authority G2, O=Google Inc, C=US
  Note Before: 2016-07-28 11:40:00 +0000 UTC
  Note After: 2016-10-20 11:40:00 +0000 UTC
  Subject Alternative Name (SAN):
	  DNSName[1]: www.google.com

Testing connection...

Supported ciphers:
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  TLS_RSA_WITH_RC4_128_SHA
  TLS_ECDHE_RSA_WITH_RC4_128_SHA
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  TLS_RSA_WITH_3DES_EDE_CBC_SHA
  TLS_RSA_WITH_AES_256_CBC_SHA
  TLS_RSA_WITH_AES_128_CBC_SHA
Unsupported ciphers:
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA

Total app time:  113.284246ms
```
Note: Any of the flags can be combined and in any order.
## Help
```console
$ tlsinfo -h
TLS Info
  version 1.0.0-DEV
Usage of tlsinfo:
  -s string
    	the filename for saving the server certificate
  -t string
    	the filename for the trusted CAs (PEM encoded)
  -test
    	when enabled, all ciphers will be tested
  -u string
    	the url used for the connection (default "https://www.google.com")
```
