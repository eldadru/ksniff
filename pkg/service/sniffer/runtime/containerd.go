package runtime

import (
	"fmt"

	"ksniff/utils"
)

type ContainerdBridge struct {
	tcpdumpContainerName string
	socketPath           string
}

func NewContainerdBridge() *ContainerdBridge {
	return &ContainerdBridge{}
}

func (d ContainerdBridge) NeedsPid() bool {
	return false
}

func (d ContainerdBridge) BuildInspectCommand(string) []string {
	panic("Containerd doesn't need this implemented")
}

func (d ContainerdBridge) ExtractPid(inspection string) (*string, error) {
	panic("Containerd doesn't need this implemented")
}

func (d ContainerdBridge) GetDefaultSocketPath() string {
	return "/run/containerd/containerd.sock"
}

func (d *ContainerdBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string, socketPath string, tcpdumpImage string) []string {
	d.tcpdumpContainerName = "ksniff-container-" + utils.GenerateRandomString(8)
	d.socketPath = socketPath
	tcpdumpCommand := d.buildTcpdumpCommand(netInterface, filter)
	runTcpdumpCommand := fmt.Sprintf(`
    netns=$(crictl inspect %s | jq '.info.runtimeSpec.linux.namespaces[] | select(.type == "network") | .path' | tr -d '"')
    exec chroot /host ctr -a ${CONTAINERD_SOCKET} run --rm --with-ns "network:${netns}" %s %s %s
    `, *containerId, tcpdumpImage, d.tcpdumpContainerName, tcpdumpCommand,
	)
	return d.buildFullCommand(d.socketPath, tcpdumpImage, runTcpdumpCommand)
}

func (d *ContainerdBridge) BuildNodeWideTcpdumpCommand(netInterface string, filter string, socketPath string, tcpdumpImage string) []string {
	d.tcpdumpContainerName = "ksniff-container-" + utils.GenerateRandomString(8)
	d.socketPath = socketPath
	tcpdumpCommand := d.buildTcpdumpCommand(netInterface, filter)
	runTcpdumpCommand := fmt.Sprintf(`
    # Run container with host network namespace for node-wide sniffing
    exec chroot /host ctr -a ${CONTAINERD_SOCKET} run --rm --net-host %s %s %s
    `, tcpdumpImage, d.tcpdumpContainerName, tcpdumpCommand,
	)
	return d.buildFullCommand(d.socketPath, tcpdumpImage, runTcpdumpCommand)
}

func (d *ContainerdBridge) buildTcpdumpCommand(netInterface string, filter string) string {
	return fmt.Sprintf("tcpdump -i %s -U -w - %s", netInterface, filter)
}

func (d *ContainerdBridge) buildFullCommand(socketPath string, tcpdumpImage string, runTcpdumpCommand string,) []string {
	shellScript := fmt.Sprintf(`
    set -ex
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_RUNTIME_ENDPOINT="unix:///host${CONTAINERD_SOCKET}"
    export IMAGE_SERVICE_ENDPOINT=${CONTAINER_RUNTIME_ENDPOINT}
    crictl pull %s >/dev/null
		%s
		`, socketPath, tcpdumpImage, runTcpdumpCommand,
	)
	return []string{"/bin/sh", "-c", shellScript}
}

func (d *ContainerdBridge) BuildCleanupCommand() []string {
	shellScript := fmt.Sprintf(
		`
    set -ex
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_ID="%s"
    chroot /host ctr -a ${CONTAINERD_SOCKET} task kill -s SIGKILL ${CONTAINER_ID}
    `, d.socketPath, d.tcpdumpContainerName,
	)
	command := []string{"/bin/sh", "-c", shellScript}
	return command
}

func (d ContainerdBridge) GetDefaultImage() string {
	return "docker.io/hamravesh/ksniff-helper:v3"
}

func (d *ContainerdBridge) GetDefaultTCPImage() string {
	return "docker.io/maintained/tcpdump:latest"
}
