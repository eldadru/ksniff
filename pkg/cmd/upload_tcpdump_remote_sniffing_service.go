package cmd

import (
	log "github.com/sirupsen/logrus"
	"io"
	"ksniff/kube"
)

type UploadTcpdumpRemoteSniffingService struct {
	sniffOptions         *SniffOptions
	kubernetesApiService kube.KubernetesApiService
}

func NewUploadTcpdumpRemoteSniffingService(options *SniffOptions, service kube.KubernetesApiService) RemoteSniffingService {
	return &UploadTcpdumpRemoteSniffingService{sniffOptions: options, kubernetesApiService: service}
}

func (u *UploadTcpdumpRemoteSniffingService) Setup() error {
	err := u.uploadTcpdump()
	if err != nil {
		return err
	}

	return nil
}

func (u *UploadTcpdumpRemoteSniffingService) Cleanup() error {
	log.Info("teardown upload static tcpdump sniffing")
	// TODO: complete
	return nil
}

func (u *UploadTcpdumpRemoteSniffingService) Start(stdOut io.Writer) error {
	log.Info("start sniffing on remote container")

	command := []string{u.sniffOptions.userSpecifiedRemoteTcpdumpPath, "-i", u.sniffOptions.userSpecifiedInterface,
		"-U", "-w", "-", u.sniffOptions.userSpecifiedFilter}

	exitCode, err := u.kubernetesApiService.ExecuteCommand(u.sniffOptions.userSpecifiedPodName, u.sniffOptions.userSpecifiedContainer, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("executing sniffer failed, exit code: '%d'", exitCode)
		return err
	}

	log.Infof("done sniffing on remote container")

	return nil
}

func (u *UploadTcpdumpRemoteSniffingService) uploadTcpdump() error {
	log.Infof("uploading static tcpdump binary from: '%s' to: '%s'",
		u.sniffOptions.userSpecifiedLocalTcpdumpPath, u.sniffOptions.userSpecifiedRemoteTcpdumpPath)

	err := u.kubernetesApiService.UploadFile(u.sniffOptions.userSpecifiedLocalTcpdumpPath,
		u.sniffOptions.userSpecifiedRemoteTcpdumpPath, u.sniffOptions.userSpecifiedPodName, u.sniffOptions.userSpecifiedContainer)

	if err != nil {
		log.WithError(err).Errorf("failed uploading static tcpdump binary to container, please verify the remote container has tar installed")
	}

	log.Info("tcpdump uploaded successfully")

	return nil
}
