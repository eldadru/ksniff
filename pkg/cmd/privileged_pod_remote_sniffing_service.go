package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"k8s.io/api/core/v1"
	"ksniff/kube"
)

type PrivilegedPodRemoteSniffingService struct {
	sniffOptions         *SniffOptions
	privilegedPod        *v1.Pod
	kubernetesApiService kube.KubernetesApiService
}

func NewPrivilegedPodRemoteSniffingService(options *SniffOptions, service kube.KubernetesApiService) RemoteSniffingService {
	return &PrivilegedPodRemoteSniffingService{sniffOptions: options, kubernetesApiService: service}
}

func (p *PrivilegedPodRemoteSniffingService) Setup() error {
	var err error

	log.Infof("creating privileged pod on node: '%s'", p.sniffOptions.podNodeName)

	p.privilegedPod, err = p.kubernetesApiService.CreatePrivilegedPod(p.sniffOptions.podNodeName)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", p.sniffOptions.podNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", p.privilegedPod.Name, p.sniffOptions.podNodeName)

	return nil
}

func (p *PrivilegedPodRemoteSniffingService) Cleanup() error {
	log.Infof("removing pod: '%s'", p.privilegedPod.Name)

	err := p.kubernetesApiService.DeletePod(p.privilegedPod.Name)
	if err != nil {
		log.WithError(err).Errorf("failed to remove pod: '%s", p.privilegedPod.Name)
	}

	log.Infof("pod: '%s' removed successfully", p.privilegedPod.Name)

	return nil
}

func (p *PrivilegedPodRemoteSniffingService) Start(stdOut io.Writer) error {
	log.Info("starting remote sniffing using privileged pod")

	command := []string{"docker", "run", "--rm", fmt.Sprintf("--net=container:%s", p.sniffOptions.containerId),
		"corfr/tcpdump", "-i", p.sniffOptions.userSpecifiedInterface, "-U", "-w", "-", p.sniffOptions.userSpecifiedFilter}

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedPod.Spec.Containers[0].Name, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
	}

	log.Info("remote sniffing using privileged pod completed")

	return nil
}
