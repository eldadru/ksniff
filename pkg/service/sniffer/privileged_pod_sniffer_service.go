package sniffer

import (
	"bytes"
	"io"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer/runtime"
)

type PrivilegedPodSnifferService struct {
	settings                *config.KsniffSettings
	privilegedPod           *v1.Pod
	privilegedContainerName string
	targetProcessId         *string
	kubernetesApiService    kube.KubernetesApiService
	runtimeBridge           runtime.ContainerRuntimeBridge
}

func NewPrivilegedPodRemoteSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService, bridge runtime.ContainerRuntimeBridge) SnifferService {
	return &PrivilegedPodSnifferService{settings: options, privilegedContainerName: "ksniff-privileged", kubernetesApiService: service, runtimeBridge: bridge}
}

func (p *PrivilegedPodSnifferService) Setup() error {
	var err error

	log.Infof("creating privileged pod on node: '%s'", p.settings.DetectedPodNodeName)

	if p.settings.UseDefaultImage {
		p.settings.Image = p.runtimeBridge.GetDefaultImage()
	}

	if p.settings.UseDefaultTCPDumpImage {
		p.settings.TCPDumpImage = p.runtimeBridge.GetDefaultTCPImage()
	}

	if p.settings.UseDefaultSocketPath {
		p.settings.SocketPath = p.runtimeBridge.GetDefaultSocketPath()
	}

	p.privilegedPod, err = p.kubernetesApiService.CreatePrivilegedPod(
		p.settings.DetectedPodNodeName,
		p.privilegedContainerName,
		p.settings.Image,
		p.settings.SocketPath,
		p.settings.UserSpecifiedPodCreateTimeout,
	)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", p.settings.DetectedPodNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", p.privilegedPod.Name, p.settings.DetectedPodNodeName)

	if p.runtimeBridge.NeedsPid() {
		var buff bytes.Buffer
		command := p.runtimeBridge.BuildInspectCommand(p.settings.DetectedContainerId)
		exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedContainerName, command, &buff)
		if err != nil {
			log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
		}
		p.targetProcessId, err = p.runtimeBridge.ExtractPid(buff.String())
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *PrivilegedPodSnifferService) Cleanup() error {
	log.Infof("removing privileged container: '%s'", p.privilegedContainerName)

	command := p.runtimeBridge.BuildCleanupCommand()

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedContainerName, command, &kube.NopWriter{})
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

	command := p.runtimeBridge.BuildTcpdumpCommand(
		&p.settings.DetectedContainerId,
		p.settings.UserSpecifiedInterface,
		p.settings.UserSpecifiedFilter,
		p.targetProcessId,
		p.settings.SocketPath,
		p.settings.TCPDumpImage,
	)

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedContainerName, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
		return err
	}

	log.Info("remote sniffing using privileged pod completed")

	return nil
}
