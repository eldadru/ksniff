package runtime

import (
	"fmt"
	"ksniff/utils"
)

type DockerBridge struct {
	socketPathOptions    []string
	tcpdumpContainerName string
	socketPath           string
}

func NewDockerBridge() *DockerBridge {
	return &DockerBridge{
		socketPathOptions: []string{
			"/host/var/run/docker.sock",
			"/host/run/docker.sock",
		},
	}
}

func (d DockerBridge) NeedsPid() bool {
	return false
}

func (d DockerBridge) NeedsSocket() bool {
	return true
}

func (d DockerBridge) GetSocketPathOptions() []string {
	return d.socketPathOptions
}

func (d *DockerBridge) SetSocketPath(socketPath string) {
	d.socketPath = socketPath
}

func (d DockerBridge) BuildInspectCommand(string) []string {
	panic("Docker doesn't need this implemented")
}

func (d DockerBridge) ExtractPid(inspection string) (*string, error) {
	panic("Docker doesn't need this implemented")
}

func (d *DockerBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string) []string {
	d.tcpdumpContainerName = "ksniff-container-" + utils.GenerateRandomString(8)
	containerNameFlag := fmt.Sprintf("--name=%s", d.tcpdumpContainerName)

	command := []string{"docker", "--host", fmt.Sprintf("unix://%s", d.socketPath),
		"run", "--rm", containerNameFlag,
		fmt.Sprintf("--net=container:%s", *containerId), "maintained/tcpdump", "-i",
		netInterface, "-U", "-w", "-", filter}

	return command
}

func (d DockerBridge) BuildCleanupCommand() []string {
	return []string{"docker", "rm", "-f", d.tcpdumpContainerName}
}

func (d DockerBridge) GetDefaultImage() string {
	return "docker"
}
