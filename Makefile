VERSION=1.0.0-DEV

PKG=github.com/spazbite187/snatchtls
BINARY=snatchtls
OUTPUT=$(GOPATH)/bin/${BINARY}
BUILDTIME=`date -u "+%Y%m%d%H%M%S"`
COMMIT=`git log --oneline -n 1 --format="%h"`

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILDTIME} -X main.Commit=${COMMIT}"

default: some

all: format vet lint test build

some: format test build

format:
	go fmt ${PKG}/...

vet:
	go vet ${PKG}/...

lint:
	golint ${PKG}/...

test:
	go test -v ${PKG}/...

build: build_mac build_linux build_arm

build_mac:
	env GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${OUTPUT}-mac ${PKG}

build_linux:
	env GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${OUTPUT}-linux ${PKG}

build_arm:
	env GOOS=linux GOARCH=arm GOARM=7 go build ${LDFLAGS} -o ${OUTPUT}-arm ${PKG}
