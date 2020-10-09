package runtime

import (
	"fmt"
	"ksniff/utils"
)

type DockerBridge struct {
	tcpdumpContainerName string
}

func NewDockerBridge() DockerBridge{
	return DockerBridge{}
}

func (d DockerBridge) NeedsPid() bool {
	return false
}

func (d DockerBridge) BuildInspectCommand(string) []string {
	panic("Docker doesn't need this implemented")
}

func (d DockerBridge) ExtractPid(inspection string) (*string, error) {
	panic("Docker doesn't need this implemented")
}

func (d DockerBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string) []string {
	d.tcpdumpContainerName = "ksniff-container-" + utils.GenerateRandomString(8)
	containerNameFlag := fmt.Sprintf("--name=%s", d.tcpdumpContainerName)

	command := []string{"docker", "--host", "unix:///host/var/run/docker.sock",
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
