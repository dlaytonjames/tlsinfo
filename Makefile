VERSION=1.0.0-DEV

PKG=github.com/spazbite187/snatchtls
BINARY=snatchtls
OUTPUT=$(GOPATH)/bin/${BINARY}
BUILDTIME=`date -u "+%Y%m%d%H%M%S"`
COMMIT=`git log --oneline -n 1 --format="%h"`

LDFLAGS=-ldflags "-X ${PKG}/client.Version=${VERSION} -X ${PKG}/client.BuildTime=${BUILDTIME} -X ${PKG}/client.Commit=${COMMIT}"

default: all

all: format vet lint test build

format:
	go fmt ${PKG}/...

vet:
	go vet ${PKG}/...

lint:
	golint ${PKG}/...

test:
	go test -v ${PKG}/...

build:
	go build ${LDFLAGS} -o ${OUTPUT} ${PKG}
