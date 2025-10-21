package runtime

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerdBridge_NeedsPid(t *testing.T) {
	bridge := NewContainerdBridge()
	assert.False(t, bridge.NeedsPid())
}

func TestContainerdBridge_GetDefaultSocketPath(t *testing.T) {
	bridge := NewContainerdBridge()
	assert.Equal(t, "/run/containerd/containerd.sock", bridge.GetDefaultSocketPath())
}

func TestContainerdBridge_GetDefaultImage(t *testing.T) {
	bridge := NewContainerdBridge()
	assert.Equal(t, "docker.io/hamravesh/ksniff-helper:v3", bridge.GetDefaultImage())
}

func TestContainerdBridge_GetDefaultTCPImage(t *testing.T) {
	bridge := NewContainerdBridge()
	assert.Equal(t, "docker.io/maintained/tcpdump:latest", bridge.GetDefaultTCPImage())
}

func TestContainerdBridge_BuildTcpdumpCommand(t *testing.T) {
	bridge := NewContainerdBridge()
	containerId := "test-container-id"
	netInterface := "eth0"
	filter := "port 80"
	socketPath := "/run/containerd/containerd.sock"
	tcpdumpImage := "docker.io/maintained/tcpdump:latest"

	command := bridge.BuildTcpdumpCommand(&containerId, netInterface, filter, nil, socketPath, tcpdumpImage)

	assert.Equal(t, 3, len(command))
	assert.Equal(t, "/bin/sh", command[0])
	assert.Equal(t, "-c", command[1])

	script := command[2]

	// Verify the script contains multi-distribution compatibility check
	assert.Contains(t, script, "if chroot /host which ctr >/dev/null 2>&1; then")
	assert.Contains(t, script, "CTR_CMD=\"ctr\"")
	assert.Contains(t, script, "elif chroot /host test -f /var/lib/rancher/rke2/bin/ctr; then")
	assert.Contains(t, script, "CTR_CMD=\"/var/lib/rancher/rke2/bin/ctr\"")
	assert.Contains(t, script, "elif chroot /host which k3s >/dev/null 2>&1; then")
	assert.Contains(t, script, "CTR_CMD=\"k3s ctr\"")

	// Verify the script uses the CTR_CMD variable
	assert.Contains(t, script, "chroot /host ${CTR_CMD} -a ${CONTAINERD_SOCKET}")
	
	// Verify other essential parts of the script
	assert.Contains(t, script, "crictl pull")
	assert.Contains(t, script, "crictl inspect")
	assert.Contains(t, script, "tcpdump -i eth0 -U -w - port 80")
	assert.Contains(t, script, socketPath)
	assert.Contains(t, script, containerId)
	assert.Contains(t, script, tcpdumpImage)
	
	// Verify the container name was set
	assert.NotEmpty(t, bridge.tcpdumpContainerName)
	assert.True(t, strings.HasPrefix(bridge.tcpdumpContainerName, "ksniff-container-"))
}

func TestContainerdBridge_BuildCleanupCommand(t *testing.T) {
	bridge := NewContainerdBridge()

	// First build a tcpdump command to set the container name and socket path
	containerId := "test-container-id"
	netInterface := "eth0"
	filter := "port 80"
	socketPath := "/run/containerd/containerd.sock"
	tcpdumpImage := "docker.io/maintained/tcpdump:latest"

	bridge.BuildTcpdumpCommand(&containerId, netInterface, filter, nil, socketPath, tcpdumpImage)

	// Now build the cleanup command
	command := bridge.BuildCleanupCommand()

	assert.Equal(t, 3, len(command))
	assert.Equal(t, "/bin/sh", command[0])
	assert.Equal(t, "-c", command[1])

	script := command[2]

	// Verify the script contains multi-distribution compatibility check
	assert.Contains(t, script, "if chroot /host which ctr >/dev/null 2>&1; then")
	assert.Contains(t, script, "CTR_CMD=\"ctr\"")
	assert.Contains(t, script, "elif chroot /host test -f /var/lib/rancher/rke2/bin/ctr; then")
	assert.Contains(t, script, "CTR_CMD=\"/var/lib/rancher/rke2/bin/ctr\"")
	assert.Contains(t, script, "elif chroot /host which k3s >/dev/null 2>&1; then")
	assert.Contains(t, script, "CTR_CMD=\"k3s ctr\"")

	// Verify the script uses the CTR_CMD variable
	assert.Contains(t, script, "chroot /host ${CTR_CMD} -a ${CONTAINERD_SOCKET}")
	
	// Verify the cleanup command
	assert.Contains(t, script, "task kill -s SIGKILL")
	assert.Contains(t, script, socketPath)
	assert.Contains(t, script, bridge.tcpdumpContainerName)
}

func TestContainerdBridge_BuildInspectCommand_Panics(t *testing.T) {
	bridge := NewContainerdBridge()
	assert.Panics(t, func() { bridge.BuildInspectCommand("test-id") })
}

func TestContainerdBridge_ExtractPid_Panics(t *testing.T) {
	bridge := NewContainerdBridge()
	assert.Panics(t, func() { bridge.ExtractPid("test-inspection") })
}

func TestContainerdBridge_BuildTcpdumpCommand_CustomCtrPath(t *testing.T) {
	bridge := NewContainerdBridge()
	bridge.SetCtrPath("k3s ctr") // Set custom ctr path

	containerId := "test-container-id"
	netInterface := "eth0"
	filter := "port 80"
	socketPath := "/run/k3s/containerd/containerd.sock"
	tcpdumpImage := "docker.io/maintained/tcpdump:latest"

	command := bridge.BuildTcpdumpCommand(&containerId, netInterface, filter, nil, socketPath, tcpdumpImage)

	assert.Equal(t, 3, len(command))
	assert.Equal(t, "/bin/sh", command[0])
	assert.Equal(t, "-c", command[1])

	script := command[2]

	// Verify the script uses the custom ctr path directly
	assert.Contains(t, script, `CTR_CMD="k3s ctr"`)

	// Verify it does NOT contain auto-detection logic when custom path is provided
	assert.NotContains(t, script, "if chroot /host which ctr")

	// Verify other essential parts of the script
	assert.Contains(t, script, "crictl pull")
	assert.Contains(t, script, "crictl inspect")
	assert.Contains(t, script, "tcpdump -i eth0 -U -w - port 80")
	assert.Contains(t, script, socketPath)
	assert.Contains(t, script, containerId)
	assert.Contains(t, script, tcpdumpImage)
}

func TestContainerdBridge_BuildCleanupCommand_CustomCtrPath(t *testing.T) {
	bridge := NewContainerdBridge()
	bridge.SetCtrPath("/var/lib/rancher/rke2/bin/ctr") // Set custom RKE2 ctr path

	// First build a tcpdump command to set the container name and socket path
	containerId := "test-container-id"
	netInterface := "eth0"
	filter := "port 80"
	socketPath := "/run/k3s/containerd/containerd.sock"
	tcpdumpImage := "docker.io/maintained/tcpdump:latest"

	bridge.BuildTcpdumpCommand(&containerId, netInterface, filter, nil, socketPath, tcpdumpImage)

	// Now build the cleanup command
	command := bridge.BuildCleanupCommand()

	assert.Equal(t, 3, len(command))
	assert.Equal(t, "/bin/sh", command[0])
	assert.Equal(t, "-c", command[1])

	script := command[2]

	// Verify the script uses the custom ctr path directly
	assert.Contains(t, script, `CTR_CMD="/var/lib/rancher/rke2/bin/ctr"`)

	// Verify it does NOT contain auto-detection logic when custom path is provided
	assert.NotContains(t, script, "if chroot /host which ctr")

	// Verify the cleanup command
	assert.Contains(t, script, "task kill -s SIGKILL")
	assert.Contains(t, script, socketPath)
	assert.Contains(t, script, bridge.tcpdumpContainerName)
}

