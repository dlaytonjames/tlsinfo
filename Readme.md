## TLS Info (tlsinfo)

tlsinfo is a command line tool for getting the connection details of a TLS end point. In test mode it will
return a list of allowed TLS ciphers.

## Install
```console
$ go get -u github.com/spazbite187/tlsinfo
$ go install github.com/spazbite187/tlsinfo/...
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
  Response time: 116.279735ms
  HTTP response status: 200 OK
  HTTP protocol: HTTP/2.0
  TLS version: TLSv1.2
  TLS cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  Stapled OCSP response: false
Server certificate:
  Serial=44b848caa05a0883
  Subject DN: CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US
  Issuer DN: CN=Google Internet Authority G2, O=Google Inc, C=US
  Note Before: 2016-11-10 15:31:38 +0000 UTC
  Note After: 2017-02-02 15:30:00 +0000 UTC
  Subject Alternative Name (SAN):
	  DNSName[1]: www.google.com
Valid paths:
 path: 1
  certificate 1: CN=GeoTrust Global CA, O=GeoTrust Inc., C=US (serial=23456)
  certificate 2: CN=Google Internet Authority G2, O=Google Inc, C=US (serial=23a92)
  certificate 3: CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US (serial=44b848caa05a0883)

Total app time:  116.279735ms
```
To run with a specific URL, use the `-u` flag to specify the TLS endpoint.
```console
$ tlsinfo -u https://www.curttech.net
...
```
To run with a custom trust store, use the `-t` flag to specify the file containing a list of PEM encoded
CA certificates.
```console
$ tlsinfo -t trustList.pem
...
```
To run in test mode, use the `-test` flag. Test mode will attempt to connect using all the configure
TLS ciphers and report on the results.
```console
$ tlsinfo -u https://www.curttech.net -test
TLS Info
  version 1.0.0-DEV

Trust: (using system trust)
  URL: https://www.curttech.net

Connection info:
  Response time: 150.36779ms
  HTTP response status: 200 OK
  HTTP protocol: HTTP/1.1
  TLS version: TLSv1.2
  TLS cipher: TLS_RSA_WITH_AES_128_CBC_SHA
  Stapled OCSP response: false
Server certificate:
  Serial=3bfd8804545d90bc57505af3631af375681
  Subject DN: CN=www.curttech.net
  Issuer DN: CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US
  Note Before: 2016-11-06 22:42:00 +0000 UTC
  Note After: 2017-02-04 22:42:00 +0000 UTC
  Subject Alternative Name (SAN):
	  DNSName[1]: cannikin.curttech.net
	  DNSName[2]: nismo.curttech.net
	  DNSName[3]: plex.curttech.net
	  DNSName[4]: sierra.curttech.net
	  DNSName[5]: www.curttech.net
Valid paths:
 path: 1
  certificate 1: CN=DST Root CA X3, O=Digital Signature Trust Co. (serial=44afb080d6a327ba893039862ef8406b)
  certificate 2: CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US (serial=a0141420000015385736a0b85eca708)
  certificate 3: CN=www.curttech.net (serial=3bfd8804545d90bc57505af3631af375681)
 path: 2
  certificate 1: CN=DST Root CA X3, O=Digital Signature Trust Co. (serial=44afb080d6a327ba893039862ef8406b)
  certificate 2: CN=DST Root CA X3, O=Digital Signature Trust Co. (serial=44afb080d6a327ba893039862ef8406b)
  certificate 3: CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US (serial=a0141420000015385736a0b85eca708)
  certificate 4: CN=www.curttech.net (serial=3bfd8804545d90bc57505af3631af375681)

Testing connection...

Supported ciphers:
  TLS_RSA_WITH_AES_128_CBC_SHA
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  TLS_RSA_WITH_AES_256_CBC_SHA
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Unsupported ciphers:
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_RSA_WITH_RC4_128_SHA
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  TLS_RSA_WITH_RC4_128_SHA
  TLS_RSA_WITH_3DES_EDE_CBC_SHA
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

Total app time:  238.151375ms
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
