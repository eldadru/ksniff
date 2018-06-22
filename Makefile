PLUGIN_FOLDER=~/.kube/plugins/sniff

install: static-tcpdump install-plugin

plugin-folder:
	mkdir -p ~/.kube/plugins/sniff

install-plugin: plugin-folder
	cp ksniff.sh plugin.yaml ${PLUGIN_FOLDER}
	chmod +x ${PLUGIN_FOLDER}/ksniff.sh

install-static-tcpdump: plugin-folder static-tcpdump
	cp static-tcpdump ${PLUGIN_FOLDER}

static-tcpdump:
	wget http://www.tcpdump.org/release/tcpdump-4.9.2.tar.gz
	tar -xvf tcpdump-4.9.2.tar.gz
	cd tcpdump-4.9.2 && CFLAGS=-static ./configure --without-crypto && make
	mv tcpdump-4.9.2/tcpdump ./static-tcpdump
	rm -rf tcpdump-4.9.2 tcpdump-4.9.2.tar.gz
