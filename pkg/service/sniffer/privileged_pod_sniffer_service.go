package sniffer

import (
	"fmt"
	"io"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/utils"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type PrivilegedPodSnifferService struct {
	settings                *config.KsniffSettings
	privilegedPod           *v1.Pod
	privilegedContainerName string
	kubernetesApiService    kube.KubernetesApiService
}

func NewPrivilegedPodRemoteSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService) SnifferService {
	return &PrivilegedPodSnifferService{settings: options, kubernetesApiService: service}
}

func (p *PrivilegedPodSnifferService) Setup() error {
	var err error

	log.Infof("creating privileged pod on node: '%s'", p.settings.DetectedPodNodeName)

	p.privilegedPod, err = p.kubernetesApiService.CreatePrivilegedPod(p.settings.DetectedPodNodeName)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", p.settings.DetectedPodNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", p.privilegedPod.Name, p.settings.DetectedPodNodeName)

	return nil
}

func (p *PrivilegedPodSnifferService) Cleanup() error {
	log.Infof("removing privileged container: '%s'", p.privilegedContainerName)

	command := []string{"docker", "rm", "-f", p.privilegedContainerName}

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedPod.Spec.Containers[0].Name, command, &kube.NopWriter{})
	if err != nil {
		log.WithError(err).Errorf("failed to remove privileged container: '%s', exit code: '%d', "+
			"please manually remove it", p.privilegedContainerName, exitCode)
	} else {
		log.Infof("privileged container: '%s' removed successfully", p.privilegedContainerName)
	}

	log.Infof("removing pod: '%s'", p.privilegedPod.Name)

	err = p.kubernetesApiService.DeletePod(p.privilegedPod.Name)
	if err != nil {
		log.WithError(err).Errorf("failed to remove pod: '%s", p.privilegedPod.Name)
		return err
	}

	log.Infof("pod: '%s' removed successfully", p.privilegedPod.Name)

	return nil
}

func (p *PrivilegedPodSnifferService) Start(stdOut io.Writer) error {
	log.Info("starting remote sniffing using privileged pod")

	p.privilegedContainerName = "ksniff-container-" + utils.GenerateRandomString(8)
	containerNameFlag := fmt.Sprintf("--name=%s", p.privilegedContainerName)

	command := []string{"docker", "run", "--rm", containerNameFlag,
		fmt.Sprintf("--net=container:%s", p.settings.DetectedContainerId), "corfr/tcpdump", "-i",
		p.settings.UserSpecifiedInterface, "-U", "-w", "-", p.settings.UserSpecifiedFilter}

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedPod.Spec.Containers[0].Name, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
	}

	log.Info("remote sniffing using privileged pod completed")

	return nil
}
