package runtime

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExtractPid(t *testing.T) {
	bridge := NewDockerBridge()
	assert.Panics(t, func(){ bridge.ExtractPid("") })
}

func TestInspectCommand(t *testing.T) {
	bridge := NewDockerBridge()
	assert.Panics(t, func(){ bridge.BuildInspectCommand("") })
}

