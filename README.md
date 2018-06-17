# ksniff
A dead simple bash script that utilize Kubectl, tcpdump and Wireshark to start a remote capture
on any pod in you Kubernetes cluster.

You get the full power of Wireshark with minimal impact on your running pods.

### Intro
** Still WIP **

When working with micro-services, many times it's very helpful to get a capture of the network
activity between your micro-service and it's dependencies.

ksniff use kubectl to upload a statically compiled tcpdump binary to your pod and redirecting it's
output to your local Wireshark for smooth network debugging experience.

### Usage
The current script depends on a static tcpdump binary placed in "/tcpdump-static"

To compile a static tcpdump binary:

1. Download and extract tcpdump source
2. cd tcpdump source directoyy
3. CFLAGS=-static ./configure --without-crypto
4. make

You should now have a statically compiled tcpdump file, copy it to "/tcpdump-static"

Now you ready to run the script (make sure you have wireshark installed)

./ksniff <POD_NAME> <CONTAINER_NAME>

### Future Work
1. More robust script
2. better documentation
3. Use the future support of "kubectl debug" feature - https://github.com/kubernetes/community/pull/649
 
