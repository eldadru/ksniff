package cmd

import (
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"ksniff/pkg/config"
	"strings"

	"testing"
)

func TestComplete_NotEnoughArguments(t *testing.T) {
	// given
	sniff := NewKsniff(&config.KsniffSettings{})
	cmd := &cobra.Command{}
	var commands []string

	// when
	err := sniff.Complete(cmd, commands)

	// then
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not enough arguments"))
}

func TestComplete_EmptyPodName(t *testing.T) {
	// given
	sniff := NewKsniff(&config.KsniffSettings{})
	cmd := &cobra.Command{}
	var commands []string

	// when
	err := sniff.Complete(cmd, append(commands, ""))

	// then
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "pod name is empty"))
}

func TestComplete_PodNameSpecified(t *testing.T) {
	// given
	sniffSettings := &config.KsniffSettings{}
	sniff := NewKsniff(sniffSettings)
	cmd := &cobra.Command{}
	var commands []string

	// when
	err := sniff.Complete(cmd, append(commands, "pod-name"))

	// then
	assert.Nil(t, err)
	assert.Equal(t, "pod-name", sniffSettings.UserSpecifiedPodName)
}
