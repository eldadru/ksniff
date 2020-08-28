package runtime

import (
	"encoding/json"
	"fmt"
)

type CrioBridge struct {
}

func NewCrioBridge() CrioBridge {
	return CrioBridge{}
}

func (c CrioBridge) NeedsPid() bool {
	return true
}

func (c CrioBridge) BuildInspectCommand(containerId string) []string {
	return []string{"chroot", "/host", "crictl", "inspect",
		"--output", "json", containerId}
}

func (c CrioBridge) ExtractPid(inspection string) (*string, error) {
	var result map[string]interface{}
	json.Unmarshal([]byte(inspection), &result)
	pid := fmt.Sprintf("%.0f", result["pid"].(float64))
	return &pid, nil
}

func (c CrioBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string) []string {
	return []string{"nsenter", "-n", "-t", *pid, "--", "tcpdump", "-i", netInterface, "-U", "-w", "-", filter}
}

func (c CrioBridge) BuildCleanupCommand() []string {
	return nil // No cleanup needed
}

func (c CrioBridge) GetDefaultImage() string {
	return "registry.access.redhat.com/rhel7/support-tools"
}