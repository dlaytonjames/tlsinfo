## Snatch TLS (snatchtls)
[![Build Status](https://travis-ci.com/spazbite187/snatchtls.svg?token=NMbRMJwwFjLPk9aX48wh&branch=master)](https://travis-ci.com/spazbite187/snatchtls)
A command line tool for getting the connection details of a TLS end point. In test mode it will return a list of
allowed TLS ciphers.

## Install
```console
$ go get -u github.com/spazbite187/snatchtls
```
## Usage
Running `snatchtls` without any arguments will use the system trust store for server certificate validation and
`https://www.google.com` as the URL.
```console
$ snatchtls
Snatch TLS
 version 1.0.0-SNAPSHOT

Trust list: (using system trust)
       URL: https://www.google.com

Connection info:
  Response time: 128.826675ms
  HTTP response status: 200 OK
  HTTP protocol: HTTP/1.1
  TLS version: TLSv1.2
  TLS cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  Stapled OCSP response: false

Server certificate:
  Issuer DN:
      CN=Google Internet Authority G2
       O=[Google Inc]
       C=[US]
  Subject DN:
      CN=www.google.com
       O=[Google Inc]
       C=[US]
  Subject Alternative Name (SAN):
	  DNSNames: [www.google.com]
	    IPAddr: []

Total app time:  129.608231ms
```
To run with a specific URL, use the `-u` flag to specify the TLS endpoint.
```console
$ snatchtls -u https://www.apple.com
```
To run with a custom trust store, use the `-t` flag to specify the file containing a list of PEM encoded
CA certificates.
```console
$ snatchtls -t trustList.pem
```
To run in test mode, use the `-test=true` flag. Test mode will attempt to connect using all the configure
TLS ciphers and report on the results.
```console
$ snatchtls -test=true
```
Note: Any of the flags can be combined and in any order.
## Help
```console
$ snatchtls -h
Snatch TLS
 version 1.0.0-SNAPSHOT
Usage of snatchtls:
  -t string
    	the filename for the trusted CAs (PEM encoded)
  -test
    	when enabled, all ciphers will be tested
  -u string
    	the url used for the connection (default "https://www.google.com")
```