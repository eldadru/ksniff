#!/usr/bin/env bash

KUBECTL_MINOR_VERSION=$(kubectl version --client=true --short=true -o json | jq .clientVersion.minor)
KUBECTL_MINOR_VERSION="${KUBECTL_MINOR_VERSION%\"}"
KUBECTL_MINOR_VERSION="${KUBECTL_MINOR_VERSION#\"}"
NEW_PLUGIN_SYSTEM_MINIMUM_KUBECTL_VERSION=12

POD_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_POD:-$1}
CONTAINER_NAME=${KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER}
NAMESPACE_NAME=${KUBECTL_PLUGINS_CURRENT_NAMESPACE}
FILTER=${KUBECTL_PLUGINS_LOCAL_FLAG_FILTER}
STATIC_TCPDUMP_NAME=static-tcpdump
STATIC_TCPDUMP_LOCAL_PATH="./"
CONTAINER_FLAG=""
NAMESPACE_FLAG=""


function usage() {
  echo "[+] Usage: ./ksniff.sh <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-f <CAPTURE FILTER>]"
	exit 1
}

if [ -z ${POD_NAME} ]; then
  usage
fi

shift

while getopts ":n:c:f:" opt; do
  case ${opt} in
    n )
        NAMESPACE_NAME=${OPTARG}
        ;;
    c )
        CONTAINER_NAME=${OPTARG}
        ;;
    f )
        FILTER=${OPTARG}
        ;;
  esac
done


if [ -n "$CONTAINER_NAME" ]; then
  CONTAINER_FLAG="-c ${CONTAINER_NAME}"
fi

if [ -n "$NAMESPACE_NAME" ]; then
  NAMESPACE_FLAG="-n ${NAMESPACE_NAME}"
fi

if [ ${KUBECTL_MINOR_VERSION} -ge ${NEW_PLUGIN_SYSTEM_MINIMUM_KUBECTL_VERSION} ]; then
  STATIC_TCPDUMP_LOCAL_PATH=/usr/local/bin/
fi

echo "[+] Sniffing on pod: '${POD_NAME}' [container: '${CONTAINER_NAME}', namespace: '${NAMESPACE_NAME}', filter: '${FILTER}']"

echo "[+] Verifying pod status"
kubectl get pod ${POD_NAME} ${NAMESPACE_FLAG}
if [[ $? -ne 0 ]]; then
  echo "[-] Pod is not existing or on different namespace"
  exit 1
fi

echo "[+] checking if tcpdump already exist"
kubectl exec ${POD_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG} -- ls -alt /${STATIC_TCPDUMP_NAME}
if [[ $? -ne 0 ]]; then
	echo "[+] couldn't find static tcpdump binary, uploading static tcpdump to container"

	if [ ! -f ${STATIC_TCPDUMP_LOCAL_PATH}${STATIC_TCPDUMP_NAME} ]; then
    echo "[-] static tcpdump was not found in path! please install it and make sure it's located on the same directory as ksniff"
    exit 1
  fi

	kubectl cp ${STATIC_TCPDUMP_LOCAL_PATH}${STATIC_TCPDUMP_NAME} ${POD_NAME}:/${STATIC_TCPDUMP_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG}
	kubectl exec ${POD_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG} -- chmod +x /${STATIC_TCPDUMP_NAME}
else
	echo "[+] static tcpdump is already installed on container!"
fi

echo "[+] Starting remote sniffing!"
kubectl exec ${POD_NAME} ${CONTAINER_FLAG} ${NAMESPACE_FLAG} -- /${STATIC_TCPDUMP_NAME} -U -w - ${FILTER} | wireshark -k -i -
