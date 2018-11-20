# ksniff

[caption="Build status", link="https://travis-ci.org/eldadru/ksniff"]

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

## Installation
Download the latest release package, unzip it and use the attached makefile:  

    unzip ksniff.zip
    make install


## Build

Requirements:
1. libpcap-dev: for tcpdump compilation (Ubuntu: sudo apt-get install libpcap-dev)
2. jq: for parsing kubectl version
3. go 1.11 or newer

Compiling:
 
    linux:      make linux
    windows:    make windows
    mac:        make darwin
 

To compile a static tcpdump binary:

    make static-tcpdump

### Usage

    kubectl < 1.12:
    kubectl plugin sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-f <CAPTURE_FILTER>] [-o OUTPUT_FILE] [-l LOCAL_TCPDUMP_FILE] [-r REMOTE_TCPDUMP_FILE]
    
    kubectl >= 1.12:
    kubectl sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-f <CAPTURE_FILTER>] [-o OUTPUT_FILE] [-l LOCAL_TCPDUMP_FILE] [-r REMOTE_TCPDUMP_FILE]
    
    POD_NAME: Required. the name of the kubernetes pod to start capture it's traffic.
    NAMESPACE_NAME: Optional. Namespace name. used to specify the target namespace to operate on.  
    CONTIANER_NAME: Optional. If omitted, the first container in the pod will be chosen.
    CAPTURE_FILTER: Optional. specify a specific tcpdump capture filter. If omitted no filter will be used.
    OUTPUT_FILE: Optional. if specified, ksniff will redirect tcpdump output to local file instead of wireshark.
    LOCAL_TCPDUMP_FILE: Optional. if specified, ksniff will use this path as the local path of the static tcpdump binary.
    REMOTE_TCPDUMP_FILE: Optional. if specified, ksniff will use the specified path as the remote path to upload static tcpdump to.
    


### Future Work
1. Instead of uploading static tcpdump, use the future support of "kubectl debug" feature 
 (https://github.com/kubernetes/community/pull/649) which should be a much cleaner solution.
 
