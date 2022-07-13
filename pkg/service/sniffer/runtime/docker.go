package runtime

import (
	"fmt"

	"ksniff/utils"
)

type DockerBridge struct {
	tcpdumpContainerName string
	cleanupCommand       []string
}

func NewDockerBridge() *DockerBridge {
	return &DockerBridge{}
}

func (d *DockerBridge) NeedsPid() bool {
	return false
}

func (d *DockerBridge) BuildInspectCommand(string) []string {
	panic("Docker doesn't need this implemented")
}

func (d *DockerBridge) ExtractPid(inspection string) (*string, error) {
	panic("Docker doesn't need this implemented")
}

func (d *DockerBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string, socketPath string, tcpdumpImage string) []string {
	d.tcpdumpContainerName = "ksniff-container-" + utils.GenerateRandomString(8)
	containerNameFlag := fmt.Sprintf("--name=%s", d.tcpdumpContainerName)

	command := []string{"docker", "--host", "unix://" + socketPath,
		"run", "--rm", "--log-driver", "none", containerNameFlag,
		fmt.Sprintf("--net=container:%s", *containerId), tcpdumpImage, "-i",
		netInterface, "-U", "-w", "-", filter}

	d.cleanupCommand = []string{"docker", "--host", "unix://" + socketPath,
		"rm", "-f", d.tcpdumpContainerName}

	return command
}

func (d *DockerBridge) BuildCleanupCommand() []string {
	return d.cleanupCommand
}

func (d *DockerBridge) GetDefaultImage() string {
	return "docker"
}

func (d *DockerBridge) GetDefaultTCPImage() string {
	return "maintained/tcpdump"
}

func (d *DockerBridge) GetDefaultSocketPath() string {
	return "/var/run/docker.sock"
}