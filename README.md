# ksniff

[![Build Status](https://travis-ci.org/eldadru/ksniff.svg?branch=master)](https://travis-ci.org/eldadru/ksniff)

A kubectl plugin that utilize tcpdump and Wireshark to start a remote capture on any pod in your
 Kubernetes cluster.

You get the full power of Wireshark with minimal impact on your running pods.

### Intro

When working with micro-services, many times it's very helpful to get a capture of the network
activity between your micro-service and it's dependencies.

ksniff use kubectl to upload a statically compiled tcpdump binary to your pod and redirecting it's
output to your local Wireshark for smooth network debugging experience.

### Demo
![Demo!](https://i.imgur.com/hWtF9r2.gif)

### Production Readiness
Ksniff [isn't production ready yet](https://github.com/eldadru/ksniff/issues/96#issuecomment-762454991), running ksniff for production workloads isn't recommended at this point.

## Installation
Installation via krew (https://github.com/GoogleContainerTools/krew)

    kubectl krew install sniff
    
For manual installation, download the latest release package, unzip it and use the attached makefile:  

    unzip ksniff.zip
    make install

### Wireshark

If you are using Wireshark with ksniff you must use at least version 3.4.0. Using older versions may result in issues reading captures (see [Known Issues](#known-issues) below).

## Build

Requirements:
1. libpcap-dev: for tcpdump compilation (Ubuntu: sudo apt-get install libpcap-dev)
2. go 1.11 or newer

Compiling:
 
    linux:      make linux
    windows:    make windows
    mac:        make darwin
 

To compile a static tcpdump binary:

    make static-tcpdump

### Usage

    kubectl < 1.12:
    kubectl plugin sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-i <INTERFACE_NAME>] [-f <CAPTURE_FILTER>] [-o OUTPUT_FILE] [-l LOCAL_TCPDUMP_FILE] [-r REMOTE_TCPDUMP_FILE]
    
    kubectl >= 1.12:
    kubectl sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-i <INTERFACE_NAME>] [-f <CAPTURE_FILTER>] [-o OUTPUT_FILE] [-l LOCAL_TCPDUMP_FILE] [-r REMOTE_TCPDUMP_FILE]
    
    POD_NAME: Required. the name of the kubernetes pod to start capture it's traffic.
    NAMESPACE_NAME: Optional. Namespace name. used to specify the target namespace to operate on.
    CONTAINER_NAME: Optional. If omitted, the first container in the pod will be chosen.
    INTERFACE_NAME: Optional. Pod Interface to capture from. If omitted, all Pod interfaces will be captured.
    CAPTURE_FILTER: Optional. specify a specific tcpdump capture filter. If omitted no filter will be used.
    OUTPUT_FILE: Optional. if specified, ksniff will redirect tcpdump output to local file instead of wireshark. Use '-' for stdout.
    LOCAL_TCPDUMP_FILE: Optional. if specified, ksniff will use this path as the local path of the static tcpdump binary.
    REMOTE_TCPDUMP_FILE: Optional. if specified, ksniff will use the specified path as the remote path to upload static tcpdump to.

#### Air gapped environments
Use `--image` and `--tcpdump-image` flags (or KUBECTL_PLUGINS_LOCAL_FLAG_IMAGE and KUBECTL_PLUGINS_LOCAL_FLAG_TCPDUMP_IMAGE environment variables) to override the default container images and use your own e.g (docker):
  
    kubectl plugin sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] --image <PRIVATE_REPO>/docker --tcpdump-image <PRIVATE_REPO>/tcpdump
   

#### Non-Privileged and Scratch Pods
To reduce attack surface and have small and lean containers, many production-ready containers runs as non-privileged user
or even as a scratch container.

To support those containers as well, ksniff now ships with the "-p" (privileged) mode.
When executed with the -p flag, ksniff will create a new pod on the remote kubernetes cluster that will have access to the node docker daemon.

ksniff will than use that pod to execute a container attached to the target container network namespace 
and perform the actual network capture.

#### Piping output to stdout
By default ksniff will attempt to start a local instance of the Wireshark GUI. You can integrate with other tools
using the `-o -` flag to pipe packet cap data to stdout.

Example using `tshark`:

    kubectl sniff pod-name -f "port 80" -o - | tshark -r -

### Contribution
More than welcome! please don't hesitate to open bugs, questions, pull requests 

### Future Work
1. Instead of uploading static tcpdump, use the future support of "kubectl debug" feature
 (https://github.com/kubernetes/community/pull/649) which should be a much cleaner solution.
 
### Known Issues

#### Wireshark and TShark cannot read pcap

*Issues [100](https://github.com/eldadru/ksniff/issues/100) and [98](https://github.com/eldadru/ksniff/issues/98)*

Wireshark may show `UNKNOWN` in Protocol column. TShark may report the following in output:

```
tshark: The standard input contains record data that TShark doesn't support.
(pcap: network type 276 unknown or unsupported)
```

This issue happens when using an old version of Wireshark or TShark to read the pcap created by ksniff. Upgrade Wireshark or TShark to resolve this issue. Ubuntu LTS versions may have this problem with stock package versions but using the [Wireshark PPA will help](https://github.com/eldadru/ksniff/issues/100#issuecomment-789503442).
