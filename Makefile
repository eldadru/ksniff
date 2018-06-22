install:
	mkdir -p ~/.kube/plugins/sniff
	cp ksniff.sh plugin.yaml ~/.kube/plugins/sniff
	chmod +x ~/.kube/plugins/sniff/ksniff.sh