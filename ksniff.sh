#!/bin/bash

POD_NAME=$1
CONTAINER_NAME=$2

function usage() {
	echo "[+] Usage: ksniff.sh <POD_NAME> <CONTAINER_NAME>"
	exit 1
}

if [ -z $POD_NAME ]; then
	usage
fi

if [ -z $CONTAINER_NAME ]; then
	usage
fi

echo "[+] Checking if tcpdump already exist"
kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- ls -alt /tcpdump-static
if [[ $? -eq 1 ]];
then
	echo "[+] No tcpdump found, uploading our static tcpdump to target continer"
	kubectl cp /tcpdump-static ${POD_NAME}:/tcpdump-static -c ${CONTAINER_NAME}
	kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- chmod +x /tcpdump-static
else
	echo "[+] Tcpdump is already installed on container!"
fi

echo "[+] Starting remote sniffing!"
kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- /tcpdump-static -s0 -w - | wireshark -k -i -
