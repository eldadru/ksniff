package sniffer

import (
	"bytes"
	"io"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer/runtime"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
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
	return &PrivilegedPodSnifferService{settings: options, kubernetesApiService: service, runtimeBridge: bridge}
}

func (p *PrivilegedPodSnifferService) Setup() error {
	var err error

	log.Infof("creating privileged pod on node: '%s'", p.settings.DetectedPodNodeName)

	image := p.settings.Image

	if p.settings.UseDefaultImage {
		image = p.runtimeBridge.GetDefaultImage()
	}

	p.privilegedPod, err = p.kubernetesApiService.CreatePrivilegedPod(p.settings.DetectedPodNodeName, image, p.settings.UserSpecifiedPodCreateTimeout)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", p.settings.DetectedPodNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", p.privilegedPod.Name, p.settings.DetectedPodNodeName)

	if p.runtimeBridge.NeedsPid() {
		var buff bytes.Buffer
		command := p.runtimeBridge.BuildInspectCommand(p.settings.DetectedContainerId)
		exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedPod.Spec.Containers[0].Name, command, &buff)
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

	if p.runtimeBridge.NeedsSocket() {
		socketPath, err := p.kubernetesApiService.GetFirstExistingFileOnPod(p.privilegedPod.Name, p.privilegedPod.Spec.Containers[0].Name, p.runtimeBridge.GetSocketPathOptions())
		if err != nil {
			log.WithError(err).Errorf("failed to find socket")
			return err
		}
		p.runtimeBridge.SetSocketPath(socketPath)
	}

	command := p.runtimeBridge.BuildTcpdumpCommand(&p.settings.DetectedContainerId, p.settings.UserSpecifiedInterface, p.settings.UserSpecifiedFilter, p.targetProcessId)

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedPod.Spec.Containers[0].Name, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
	}

	log.Info("remote sniffing using privileged pod completed")

	return nil
}
