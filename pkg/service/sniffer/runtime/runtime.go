package runtime

import "fmt"

var SupportedContainerRuntimes = []string {
	"docker",
	"cri-o",
}

type ContainerRuntimeBridge interface {
	NeedsPid() bool
	BuildInspectCommand(containerId string) []string
	ExtractPid(inspection string) (*string, error)
	BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string) []string
	BuildCleanupCommand() []string
	GetDefaultImage() string
}

func NewContainerRuntimeBridge(runtimeName string) ContainerRuntimeBridge {
	switch runtimeName {
	case "docker":
		return NewDockerBridge()
	case "cri-o":
		return NewCrioBridge()
	default:
		panic(fmt.Sprintf("Unable to build bridge to %s", runtimeName))
	}
}
