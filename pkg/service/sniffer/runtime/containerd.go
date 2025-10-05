package runtime

import (
	"fmt"
	"ksniff/utils"
)

type ContainerdBridge struct {
	tcpdumpContainerName string
	socketPath           string
	ctrPath              string // Custom ctr command path (empty = auto-detect)
}

func NewContainerdBridge() *ContainerdBridge {
	return &ContainerdBridge{}
}

// SetCtrPath configures the ctr command path for K3s/RKE2 support.
// If empty, auto-detection will be used.
func (d *ContainerdBridge) SetCtrPath(path string) {
	d.ctrPath = path
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
	tcpdumpCommand := fmt.Sprintf("tcpdump -i %s -U -w - %s", netInterface, filter)

	var ctrDetectionScript string
	if d.ctrPath != "" {
		// User specified custom ctr path
		ctrDetectionScript = fmt.Sprintf("CTR_CMD=\"%s\"", d.ctrPath)
	} else {
		// Auto-detect ctr command
		ctrDetectionScript = `# Try to find ctr command - check multiple locations for different Kubernetes distributions
    if chroot /host which ctr >/dev/null 2>&1; then
        # Standard containerd installation
        CTR_CMD="ctr"
    elif chroot /host test -f /var/lib/rancher/rke2/bin/ctr; then
        # RKE2 (Rancher Kubernetes Engine 2)
        CTR_CMD="/var/lib/rancher/rke2/bin/ctr"
    elif chroot /host which k3s >/dev/null 2>&1; then
        # K3s (ctr bundled in k3s binary)
        CTR_CMD="k3s ctr"
    else
        echo "Error: ctr command not found. Checked: standalone ctr, RKE2 (/var/lib/rancher/rke2/bin/ctr), and k3s ctr" >&2
        exit 1
    fi`
	}

	shellScript := fmt.Sprintf(`
    set -ex
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_RUNTIME_ENDPOINT="unix:///host${CONTAINERD_SOCKET}"
    export IMAGE_SERVICE_ENDPOINT=${CONTAINER_RUNTIME_ENDPOINT}
    crictl pull %s >/dev/null
    netns=$(crictl inspect %s | jq '.info.runtimeSpec.linux.namespaces[] | select(.type == "network") | .path' | tr -d '"')
    %s
    exec chroot /host ${CTR_CMD} -a ${CONTAINERD_SOCKET} run --rm --with-ns "network:${netns}" %s %s %s
    `, d.socketPath, tcpdumpImage, *containerId, ctrDetectionScript, tcpdumpImage, d.tcpdumpContainerName, tcpdumpCommand)
	command := []string{"/bin/sh", "-c", shellScript}
	return command
}

func (d *ContainerdBridge) BuildCleanupCommand() []string {
	var ctrDetectionScript string
	if d.ctrPath != "" {
		// User specified custom ctr path
		ctrDetectionScript = fmt.Sprintf("CTR_CMD=\"%s\"", d.ctrPath)
	} else {
		// Auto-detect ctr command
		ctrDetectionScript = `# Try to find ctr command - check multiple locations for different Kubernetes distributions
    if chroot /host which ctr >/dev/null 2>&1; then
        # Standard containerd installation
        CTR_CMD="ctr"
    elif chroot /host test -f /var/lib/rancher/rke2/bin/ctr; then
        # RKE2 (Rancher Kubernetes Engine 2)
        CTR_CMD="/var/lib/rancher/rke2/bin/ctr"
    elif chroot /host which k3s >/dev/null 2>&1; then
        # K3s (ctr bundled in k3s binary)
        CTR_CMD="k3s ctr"
    else
        echo "Error: ctr command not found. Checked: standalone ctr, RKE2 (/var/lib/rancher/rke2/bin/ctr), and k3s ctr" >&2
        exit 1
    fi`
	}

	shellScript := fmt.Sprintf(`
    set -ex
    export CONTAINERD_SOCKET="%s"
    export CONTAINERD_NAMESPACE="k8s.io"
    export CONTAINER_ID="%s"
    %s
    chroot /host ${CTR_CMD} -a ${CONTAINERD_SOCKET} task kill -s SIGKILL ${CONTAINER_ID}
    `, d.socketPath, d.tcpdumpContainerName, ctrDetectionScript)
	command := []string{"/bin/sh", "-c", shellScript}
	return command
}

func (d ContainerdBridge) GetDefaultImage() string {
	return "docker.io/hamravesh/ksniff-helper:v3"
}

func (d *ContainerdBridge) GetDefaultTCPImage() string {
	return "docker.io/maintained/tcpdump:latest"
}