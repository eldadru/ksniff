package runtime

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractPid(t *testing.T) {
	bridge := NewDockerBridge()
	assert.Panics(t, func() { bridge.ExtractPid("") })
}

func TestInspectCommand(t *testing.T) {
	bridge := NewDockerBridge()
	assert.Panics(t, func() { bridge.BuildInspectCommand("") })
}

func TestPrivilegedPodName(t *testing.T) {
	bridge := NewDockerBridge()
	var containerId = "container"
	var netInterface = "eth0"
	var filter = "filter"
	var pid = "pid"
	var path = "/path"
	bridge.BuildTcpdumpCommand(&containerId, netInterface, filter, &pid, path)
	assert.NotEqual(t, "", bridge.tcpdumpContainerName, "tcpdumpContainerName should have been set")
}

func TestCleanupCommand(t *testing.T) {
	bridge := NewDockerBridge()
	var containerId = "container"
	var netInterface = "eth0"
	var filter = "filter"
	var pid = "pid"
	var socketPath = "/path"
	bridge.BuildTcpdumpCommand(&containerId, netInterface, filter, &pid, socketPath)
	assert.Equal(t,
		[]string{"docker", "--host", "unix://" + socketPath, "rm", "-f", bridge.tcpdumpContainerName},
		bridge.BuildCleanupCommand(),
		"container cleanup command doesn't match")
}
