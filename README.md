## Snatch TLS (snatchtls)

### Get, Build and Install
> $ go get github.com/spazbite187/snatchtls

### Info
```
$ snatchtls -?
Snatch TLS
 version 1.0-SNAPSHOT

flag provided but not defined: -?
Usage of snatchtls:
  -trst string
    	 the filename for the trusted CAs (PEM encoded) (default "trustList.pem")
  -url string
    	the url used for the connection (default "https://www.apple.com")'
```
### Run
> $ snatchtls -trst *{tustList filename}* -url *{connection url}*
