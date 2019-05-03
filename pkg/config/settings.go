package config

type KsniffSettings struct {
	UserSpecifiedPodName           string
	UserSpecifiedInterface         string
	UserSpecifiedFilter            string
	UserSpecifiedContainer         string
	UserSpecifiedNamespace         string
	UserSpecifiedOutputFile        string
	UserSpecifiedLocalTcpdumpPath  string
	UserSpecifiedRemoteTcpdumpPath string
	UserSpecifiedVerboseMode       bool
	UserSpecifiedPrivilegedMode    bool
	DetectedPodNodeName            string
	DetectedContainerId            string
}

func NewKsniffSettings() *KsniffSettings {
	return &KsniffSettings{}
}
