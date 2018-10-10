#!/usr/bin/env bash

POD_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_POD:-$1}
CONTAINER_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER}
NAMESPACE_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_NAMESPACE}
FILTER=${KUBECTL_PLUGINS_LOCAL_FLAG_FILTER}
CONTAINER_FLAG=""
NAMESPACE_FLAG=""

function usage() {
  echo "[+] Usage: ./ksniff.sh <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-f <CAPTURE FILTER>]"
	exit 1
}

if [ -z ${POD_NAME} ]; then
	usage
fi

if [ -n "$CONTAINER_NAME" ]; then
  CONTAINER_FLAG="-c ${CONTAINER_NAME}"
fi

if [ -n "$NAMESPACE_NAME" ]; then
  NAMESPACE_FLAG="-n ${NAMESPACE_NAME}"
fi

echo "[+] Sniffing on pod: ${POD_NAME} container: ${CONTAINER_NAME} namespace: ${NAMESPACE_NAME}"

echo "[+] Verifying pod status"
kubectl get pod ${POD_NAME} ${NAMESPACE_FLAG}
if [[ $? -ne 0 ]]; then
  echo "[-] Pod is not existing or on different namespace"
  exit 1
fi

echo "[+] checking if tcpdump already exist"
kubectl exec ${POD_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG} -- ls -alt /static-tcpdump
if [[ $? -ne 0 ]]; then
	echo "[+] couldn't find static tcpdump binary, uploading static tcpdump to container"
	kubectl cp ./static-tcpdump ${POD_NAME}:/static-tcpdump ${CONTAINER_FLAG} ${NAMESPACE_FLAG}
	kubectl exec ${POD_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG} -- chmod +x /static-tcpdump
else
	echo "[+] static tcpdump is already installed on container!"
fi

echo "[+] Starting remote sniffing!"
kubectl exec ${POD_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG} -- /static-tcpdump -U -w - ${FILTER} | wireshark -k -i -
