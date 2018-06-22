#!/usr/bin/env bash

POD_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_POD:-$1}
CONTAINER_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER:-$2}
FILTER=${KUBECTL_PLUGINS_LOCAL_FLAG_FILTER}

function usage() {
  echo "[+] Usage: ./ksniff.sh <POD_NAME> <CONTAINER_NAME> [-f <CAPTURE FILTER>] [-u <TCPDUMP LOCAL PATH>]"
	exit 1
}

if [ -z ${POD_NAME} ] || [ -z ${CONTAINER_NAME} ]; then
	usage
fi

echo "[+] Checking if tcpdump already exist"
kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- ls -alt /tcpdump-static
if [[ $? -ne 0 ]];
then
	echo "[+] No tcpdump found, uploading our static tcpdump to target container"
	kubectl cp /tcpdump-static ${POD_NAME}:/tcpdump-static -c ${CONTAINER_NAME}
	kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- chmod +x /tcpdump-static
else
	echo "[+] Tcpdump is already installed on container!"
fi

echo "[+] Starting remote sniffing!"
kubectl exec ${POD_NAME} -c ${CONTAINER_NAME} -- /tcpdump-static -s0 -w - ${FILTER} | wireshark -k -i -
