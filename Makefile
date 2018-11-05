
TCPDUMP_VERSION=4.9.2
NEW_PLUGIN_SYSTEM_MINIMUM_KUBECTL_VERSION=12
KUBECTL_MINOR_VERSION=$(shell kubectl version --client=true --short=true -o json | jq .clientVersion.minor)
IS_NEW_PLUGIN_SUBSYSTEM := $(shell [ $(KUBECTL_MINOR_VERSION) -ge $(NEW_PLUGIN_SYSTEM_MINIMUM_KUBECTL_VERSION) ] && echo true)
STATIC_TCPDUMP_NAME=static-tcpdump

ifeq ($(IS_NEW_PLUGIN_SUBSYSTEM),true)
PLUGIN_FOLDER=/usr/local/bin
PLUGIN_NAME=kubectl-sniff
else
PLUGIN_FOLDER=~/.kube/plugins/sniff
PLUGIN_NAME=ksniff.sh
endif


build-all: build-linux build-windows build-macos


build-linux:
	GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o kubectl-sniff cmd/kubectl-sniff.go

build-windows:
	GO111MODULE=on GOOS=windows GOARCH=amd64 go build -o kubectl-sniff-windows cmd/kubectl-sniff.go

build-macos:
	GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -o kubectl-sniff-macos cmd/kubectl-sniff.go


install: install-static-tcpdump install-plugin

plugin-folder:
	mkdir -p ${PLUGIN_FOLDER}

install-plugin: plugin-folder
	if [ "${IS_NEW_PLUGIN_SUBSYSTEM}" != "true" ]; then \
        cp plugin.yaml ${PLUGIN_FOLDER};\
    fi

	cp ksniff.sh ${PLUGIN_FOLDER}/${PLUGIN_NAME}
	chmod +x ${PLUGIN_FOLDER}/${PLUGIN_NAME}

install-static-tcpdump: plugin-folder static-tcpdump
	mv ${STATIC_TCPDUMP_NAME} ${PLUGIN_FOLDER}

static-tcpdump:
	wget http://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz
	tar -xvf tcpdump-${TCPDUMP_VERSION}.tar.gz
	cd tcpdump-${TCPDUMP_VERSION} && CFLAGS=-static ./configure --without-crypto && make
	mv tcpdump-${TCPDUMP_VERSION}/tcpdump ./${STATIC_TCPDUMP_NAME}
	rm -rf tcpdump-${TCPDUMP_VERSION} tcpdump-${TCPDUMP_VERSION}.tar.gz

uninstall:
	if [ "${IS_NEW_PLUGIN_SUBSYSTEM}" != "true" ]; then \
        rm -f ${PLUGIN_FOLDER}/plugin.yaml;\
    fi

	rm -f ${PLUGIN_FOLDER}/${STATIC_TCPDUMP_NAME}
	rm -f ${PLUGIN_FOLDER}/${PLUGIN_NAME}