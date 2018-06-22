PLUGIN_FOLDER=~/.kube/plugins/sniff
TCPDUMP_VERSION=4.9.2

install: install-static-tcpdump install-plugin

plugin-folder:
	mkdir -p ~/.kube/plugins/sniff

install-plugin: plugin-folder
	cp ksniff.sh plugin.yaml ${PLUGIN_FOLDER}
	chmod +x ${PLUGIN_FOLDER}/ksniff.sh

install-static-tcpdump: plugin-folder static-tcpdump
	mv static-tcpdump ${PLUGIN_FOLDER}

static-tcpdump:
	wget http://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz
	tar -xvf tcpdump-${TCPDUMP_VERSION}.tar.gz
	cd tcpdump-${TCPDUMP_VERSION} && CFLAGS=-static ./configure --without-crypto && make
	mv tcpdump-${TCPDUMP_VERSION}/tcpdump ./static-tcpdump
	rm -rf tcpdump-${TCPDUMP_VERSION} tcpdump-${TCPDUMP_VERSION}.tar.gz
