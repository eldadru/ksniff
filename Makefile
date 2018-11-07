TCPDUMP_VERSION=4.9.2

build: build-linux build-windows build-macos

build-linux:
	GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o kubectl-sniff cmd/kubectl-sniff.go

build-windows:
	GO111MODULE=on GOOS=windows GOARCH=amd64 go build -o kubectl-sniff-windows cmd/kubectl-sniff.go

build-macos:
	GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -o kubectl-sniff-macos cmd/kubectl-sniff.go

static-tcpdump:
	wget http://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz
	tar -xvf tcpdump-${TCPDUMP_VERSION}.tar.gz
	cd tcpdump-${TCPDUMP_VERSION} && CFLAGS=-static ./configure --without-crypto && make
	mv tcpdump-${TCPDUMP_VERSION}/tcpdump ./${STATIC_TCPDUMP_NAME}
	rm -rf tcpdump-${TCPDUMP_VERSION} tcpdump-${TCPDUMP_VERSION}.tar.gz