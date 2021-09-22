package sniffer

import (
	"io"
	"ksniff/kube"
	"ksniff/pkg/config"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type StaticTcpdumpSnifferService struct {
	*config.StaticTCPSnifferServiceConfig
	kubernetesApiService kube.KubernetesApiService
}

func NewUploadTcpdumpRemoteSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService) SnifferService {

	
	staticSniffer := &StaticTcpdumpSnifferService{
		StaticTCPSnifferServiceConfig: &config.StaticTCPSnifferServiceConfig{
			UserSpecifiedLocalTcpdumpPath: options.UserSpecifiedLocalTcpdumpPath, 
			UserSpecifiedRemoteTcpdumpPath: options.UserSpecifiedRemoteTcpdumpPath ,
			UserSpecifiedPodName:           options.UserSpecifiedPodName ,
			UserSpecifiedContainer:         options.UserSpecifiedContainer ,
			UserSpecifiedInterface:        options.UserSpecifiedInterface ,
			UserSpecifiedFilter:            options.UserSpecifiedFilter ,
		}, 
		kubernetesApiService: service}
	
	return staticSniffer
}

func (u *StaticTcpdumpSnifferService) Setup() error {
	log.Infof("uploading static tcpdump binary from: '%s' to: '%s'",
		u.UserSpecifiedLocalTcpdumpPath, u.UserSpecifiedRemoteTcpdumpPath)

	err := u.kubernetesApiService.UploadFile(u.UserSpecifiedLocalTcpdumpPath,
		u.UserSpecifiedRemoteTcpdumpPath, u.UserSpecifiedPodName, u.UserSpecifiedContainer)

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

	command := []string{u.UserSpecifiedRemoteTcpdumpPath, "-i", u.UserSpecifiedInterface,
		"-U", "-w", "-", u.UserSpecifiedFilter}

	exitCode, err := u.kubernetesApiService.ExecuteCommand(u.UserSpecifiedPodName, u.UserSpecifiedContainer, command, stdOut)
	if err != nil || exitCode != 0 {
		return errors.Errorf("executing sniffer failed, exit code: '%d'", exitCode)
	}

	log.Infof("done sniffing on remote container")

	return nil
}
