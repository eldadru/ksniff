package sniffer

import (
	"io"
	"ksniff/kube"
	"ksniff/pkg/config"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type StaticTcpdumpSnifferService struct {
	settings             *config.KsniffSettings
	kubernetesApiService kube.KubernetesApiService
}

func NewUploadTcpdumpRemoteSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService) SnifferService {
	return &StaticTcpdumpSnifferService{settings: options, kubernetesApiService: service}
}

func (u *StaticTcpdumpSnifferService) Setup() error {
	log.Infof("uploading static tcpdump binary from: '%s' to: '%s'",
		u.settings.UserSpecifiedLocalTcpdumpPath, u.settings.UserSpecifiedRemoteTcpdumpPath)

	err := u.kubernetesApiService.UploadFile(u.settings.UserSpecifiedLocalTcpdumpPath,
		u.settings.UserSpecifiedRemoteTcpdumpPath, u.settings.UserSpecifiedPodName, u.settings.UserSpecifiedContainer)

	if err != nil {
		log.WithError(err).Errorf("failed uploading static tcpdump binary to container, please verify the remote container has tar installed")
		return err
	}

	log.Info("tcpdump uploaded successfully")

	return nil
}

func (u *StaticTcpdumpSnifferService) Cleanup() error {
	return nil
}

func (u *StaticTcpdumpSnifferService) Start(stdOut io.Writer) error {
	log.Info("start sniffing on remote container")

	command := []string{u.settings.UserSpecifiedRemoteTcpdumpPath, "-i", u.settings.UserSpecifiedInterface,
		"-U", "-w", "-", u.settings.UserSpecifiedFilter}

	exitCode, err := u.kubernetesApiService.ExecuteCommand(u.settings.UserSpecifiedPodName, u.settings.UserSpecifiedContainer, command, stdOut)
	if err != nil || exitCode != 0 {
		return errors.Errorf("executing sniffer failed, exit code: '%d'", exitCode)
	}

	log.Infof("done sniffing on remote container")

	return nil
}
