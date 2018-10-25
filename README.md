# ksniff

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

Requirements:
1. libpcap-dev: for tcpdump compilation (Ubuntu: sudo apt-get install libpcap-dev)
2. jq: for parsing kubectl version
 
You can easily install the plugin using the Makefile:

1. make install

'make install' will compile a static tcpdump binary and will copy all the required files to your plugin folder
 
if you only want to install the plugin files without compiling tcpdump use:
 
1. make install-plugin

 
### Usage

    kubectl < 1.12:
    kubectl plugin sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-f <CAPTURE_FILTER>]
    
    kubectl >= 1.12:
    kubectl sniff <POD_NAME> [-n <NAMESPACE_NAME>] [-c <CONTAINER_NAME>] [-f <CAPTURE_FILTER>]
    
    POD_NAME: Required. the name of the kubernetes pod to start capture it's traffic.
    NAMESPACE_NAME: Optional. Namespace name. used to specify the target namespace to operate on.  
    CONTIANER_NAME: Optional. If omitted, the first container in the pod will be chosen.
    CAPTURE_FILTER: Optional. specify a specific tcpdump capture filter. If omitted no filter will be used.
    


### Future Work
1. Instead of uploading static tcpdump, use the future support of "kubectl debug" feature 
 (https://github.com/kubernetes/community/pull/649) which should be a much cleaner solution.
 
