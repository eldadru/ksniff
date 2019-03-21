package cmd

import (
	"io"
)

type RemoteSniffingService interface {
	Setup() error

	Cleanup() error

	Start(stdOut io.Writer) error
}
