package runtime

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewContainerRuntimeBridge_Docker(t *testing.T) {
	bridge := NewContainerRuntimeBridge("docker")
	assert.IsType(t, DockerBridge{}, bridge)
}

func TestNewContainerRuntimeBridge_Crio(t *testing.T) {
	bridge := NewContainerRuntimeBridge("cri-o")
	assert.IsType(t, CrioBridge{}, bridge)
}

func TestNewContainerRuntimeBridge_Invalid(t *testing.T) {
	assert.Panics(t, func(){ NewContainerRuntimeBridge("i-do-not-exist") })
}