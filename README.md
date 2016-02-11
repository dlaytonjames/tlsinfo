## Snatch TLS (snatchtls)
[![Build Status](https://travis-ci.com/spazbite187/snatchtls.svg?token=NMbRMJwwFjLPk9aX48wh&branch=master)](https://travis-ci.com/spazbite187/snatchtls)

### Get, Build and Install
> $ go get github.com/spazbite187/snatchtls

### Run
>$ snatchtls -t *{tustList filename}* -u *{connection url}*

```
Snatch TLS
 version 1.0.0-SNAPSHOT

       URL: https://www.google.com
Trust list: trustList.pem

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

### Help
>$ snatchtls -h

```
Usage of snatchtls:
  -t string
    	 the filename for the trusted CAs (PEM encoded) (default "trustList.pem")
  -u string
    	the url used for the connection (default "https://www.google.com")
```