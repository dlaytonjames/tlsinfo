## Snatch TLS (snatchtls)

### Get, Build and Install
> $ go get github.com/spazbite187/snatchtls

### Info
>$ snatchtls -h

```
Usage of snatchtls:
  -trst string
    	 the filename for the trusted CAs (PEM encoded) (default "trustList.pem")
  -url string
    	the url used for the connection (default "https://www.google.com")
```
### Run
>$ snatchtls -trst *{tustList filename}* -url *{connection url}*

```
Snatch TLS
 version 1.0-SNAPSHOT

  trust list: trustList.pem
         url: https://www.google.com

Response time:  128.603108ms
HTTP response status:  200 OK
HTTP protocol:  HTTP/1.1
TLS version:  TLSv1.2
TLS cipher:  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
Server certificate:
Subject:
CN=www.google.com
O=Google Inc
C=US
[1] DNSName: www.google.com
Stapled OCSP response: false

Total app time:  129.284101ms
```
