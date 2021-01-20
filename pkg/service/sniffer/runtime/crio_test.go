package runtime

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	CRICTL_INSPECT_NO_PID_117 = `
{
  "status": {},
  "sandboxId": "0bba370d1a514cd5242f11b707dabc8cc54d0a653e39a9c787ec5be7e80ec887"
}
`

	CRICTL_INSPECT_WITH_PID_117 = `
{
  "status": {},
  "pid": 69417,
  "sandboxId": "0bba370d1a514cd5242f11b707dabc8cc54d0a653e39a9c787ec5be7e80ec887"
}
`

	CRICTL_INSPECT_WITH_PID_118 = `
{
  "status": {},
  "info": {
    "sandboxID": "549eb241ba685900fc152501be3c2c31b19e9d649c01f00496b58375e570da52",
    "pid": 827137
    }
  }
`

	CRICTL_INSPECT_NO_PID_118 = `
{
  "status": {},
  "info": {
    "sandboxID": "549eb241ba685900fc152501be3c2c31b19e9d649c01f00496b58375e570da52",
	}
}
`
)

func TestExtractPid_Empty(t *testing.T) {
	// given
	bridge := NewCrioBridge()

	// when
	result, err := bridge.ExtractPid("")

	// then
	assert.Nil(t, result)
	assert.NotNil(t, err)
}

func TestExtractPid_EmptyJson(t *testing.T) {
	// given
	bridge := NewCrioBridge()

	// when
	result, err := bridge.ExtractPid("{}")

	// then
	assert.Nil(t, result)
	assert.NotNil(t, err)
}

func TestExtractPid_NoPid117(t *testing.T) {
	// given
	bridge := NewCrioBridge()

	// when
	result, err := bridge.ExtractPid(CRICTL_INSPECT_NO_PID_117)

	// then
	assert.Nil(t, result)
	assert.NotNil(t, err)
}

func TestExtractPid_Valid117(t *testing.T) {
	// given
	bridge := NewCrioBridge()

	// when
	result, err := bridge.ExtractPid(CRICTL_INSPECT_WITH_PID_117)

	// then
	assert.Equal(t, "69417", *result)
	assert.Nil(t, err)
}

func TestExtractPid_NoPid118(t *testing.T) {
	// given
	bridge := NewCrioBridge()

	// when
	result, err := bridge.ExtractPid(CRICTL_INSPECT_NO_PID_118)

	// then
	assert.Nil(t, result)
	assert.NotNil(t, err)
}

func TestExtractPid_Valid118(t *testing.T) {
	// given
	bridge := NewCrioBridge()

	// when
	result, err := bridge.ExtractPid(CRICTL_INSPECT_WITH_PID_118)

	// then
	assert.Equal(t, "827137", *result)
	assert.Nil(t, err)
}
