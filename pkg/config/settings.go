package config

import (
	"time"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

type KsniffSettings struct {
	UserSpecifiedPodName           string
	UserSpecifiedInterface         string
	UserSpecifiedFilter            string
	UserSpecifiedPodCreateTimeout  time.Duration
	UserSpecifiedContainer         string
	UserSpecifiedNamespace         string
	UserSpecifiedOutputFile        string
	UserSpecifiedLocalTcpdumpPath  string
	UserSpecifiedRemoteTcpdumpPath string
	UserSpecifiedVerboseMode       bool
	UserSpecifiedPrivilegedMode    bool
	UserSpecifiedImage             string
	DetectedPodNodeName            string
	DetectedContainerId            string
	DetectedContainerRuntime       string
	Image                          string
	TCPDumpImage                   string
	UseDefaultImage                bool
	UseDefaultTCPDumpImage         bool
	UserSpecifiedKubeContext       string
	SocketPath                     string
	UseDefaultSocketPath           bool
}

type PrivilegedSnifferServiceConfig struct {
	DetectedContainerId           string
	DetectedContainerRuntime      string
	Image                         string
	TCPDumpImage                  string
	SocketPath                    string
	DetectedPodNodeName           string
	UserSpecifiedInterface        string
	UserSpecifiedFilter           string
	UserSpecifiedPodCreateTimeout time.Duration
}

type StaticTCPSnifferServiceConfig struct {
	UserSpecifiedLocalTcpdumpPath  string
	UserSpecifiedRemoteTcpdumpPath string
	UserSpecifiedPodName           string
	UserSpecifiedContainer         string
	UserSpecifiedInterface         string
	UserSpecifiedFilter            string
}

func NewKsniffSettings(streams genericclioptions.IOStreams) *KsniffSettings {
	return &KsniffSettings{}
}
