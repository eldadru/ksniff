package runtime

import "fmt"

var SupportedContainerRuntimes = []string{
	"docker",
	"cri-o",
	"containerd",
}

type ContainerRuntimeBridge interface {
	NeedsPid() bool
	BuildInspectCommand(containerId string) []string
	ExtractPid(inspection string) (*string, error)
	BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string, socketPath string, tcpdumpImage string) []string
	BuildCleanupCommand() []string
	GetDefaultImage() string
	GetDefaultTCPImage() string
	GetDefaultSocketPath() string
}

func NewContainerRuntimeBridge(runtimeName string) ContainerRuntimeBridge {
	switch runtimeName {
	case "docker":
		return NewDockerBridge()
	case "cri-o":
		return NewCrioBridge()
	case "containerd":
		return NewContainerdBridge()
	default:
		panic(fmt.Sprintf("Unable to build bridge to %s", runtimeName))
	}
}
