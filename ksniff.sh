#!/usr/bin/env bash

POD_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_POD:-$1}
CONTAINER_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER}
FILTER=${KUBECTL_PLUGINS_LOCAL_FLAG_FILTER}
CONTAINER_FLAG=""

function usage() {
  echo "[+] Usage: ./ksniff.sh <POD_NAME> [-c <CONTAINER_NAME>] [-f <CAPTURE FILTER>]"
	exit 1
}

if [ -z ${POD_NAME} ]; then
	usage
fi

if [ -n "$CONTAINER_NAME" ]; then
  CONTAINER_FLAG="-c ${CONTAINER_NAME}"
fi

echo "[+] Sniffing on ${POD_NAME}"

echo "[+] checking if tcpdump already exist"
kubectl exec ${POD_NAME} ${CONTAINER_FLAG} -- ls -alt /static-tcpdump
if [[ $? -ne 0 ]]; then
	echo "[+] couldn't find static tcpdump binary, uploading static tcpdump to container"
	kubectl cp ./static-tcpdump ${POD_NAME}:/static-tcpdump ${CONTAINER_FLAG}
	kubectl exec ${POD_NAME} ${CONTAINER_FLAG} -- chmod +x /static-tcpdump
else
	echo "[+] static tcpdump is already installed on container!"
fi

echo "[+] Starting remote sniffing!"
kubectl exec ${POD_NAME} ${CONTAINER_FLAG} -- /static-tcpdump -s0 -w - ${FILTER} | wireshark -k -i -
