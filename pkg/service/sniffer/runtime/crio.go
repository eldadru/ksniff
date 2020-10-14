package runtime

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

type CrioBridge struct {
}

func NewCrioBridge() *CrioBridge {
	return &CrioBridge{}
}

func (c CrioBridge) NeedsPid() bool {
	return true
}

func (c CrioBridge) NeedsDockerSocket() bool {
	return false
}

func (d *CrioBridge) SetDockerSocketPath(dockerSocketPath string) {
	panic("Cri-o doesn't need this implemented")
}

func (c CrioBridge) BuildInspectCommand(containerId string) []string {
	return []string{"chroot", "/host", "crictl", "inspect",
		"--output", "json", containerId}
}

func (c CrioBridge) ExtractPid(inspection string) (*string, error) {
	var result map[string]json.RawMessage
	var pid float64
	var err error

	err = json.Unmarshal([]byte(inspection), &result)
	if err != nil {
		return nil, err
	}

	// CRI-O changes the way it reports PID so we have to by dynamic here
	if result["pid"] != nil {
		pid, err = extractPidCrio117(result)
		if err != nil {
			return nil, errors.Wrap(err, "error getting container PID from CRI-O")
		}
	} else if result["info"] != nil {
		pid, err = extractPidCrio118(result)
		if err != nil {
			return nil, errors.Wrap(err, "error getting container PID from CRI-O")
		}
	} else {
		return nil, errors.New("unable to identify CRI-O version")
	}

	ret := fmt.Sprintf("%.0f", pid)
	return &ret, nil
}

func (c *CrioBridge) BuildTcpdumpCommand(containerId *string, netInterface string, filter string, pid *string) []string {
	return []string{"nsenter", "-n", "-t", *pid, "--", "tcpdump", "-i", netInterface, "-U", "-w", "-", filter}
}

func (c CrioBridge) BuildCleanupCommand() []string {
	return nil // No cleanup needed
}

func (c CrioBridge) GetDefaultImage() string {
	return "maintained/tcpdump"
}

// CRI-O 1.17 and older have pid as first-level attribute
func extractPidCrio117(partial map[string]json.RawMessage) (float64, error) {
	var result float64
	err := json.Unmarshal(partial["pid"], &result)
	if err != nil {
		return -1, err
	}
	return result, nil
}

// CRI-O 1.18 and later nest pid under info attribute
func extractPidCrio118(partial map[string]json.RawMessage) (float64, error) {
	var result map[string]interface{}
	err := json.Unmarshal(partial["info"], &result)
	if err != nil {
		return -1, err
	}
	return result["pid"].(float64), nil
}
