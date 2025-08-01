package sniffer

import (
	"io"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer/runtime"
)

type NodeWideSnifferService struct {
	settings                *config.KsniffSettings
	privilegedPod           *v1.Pod
	privilegedContainerName string
	kubernetesApiService    kube.KubernetesApiService
	runtimeBridge           runtime.ContainerRuntimeBridge
}

func NewNodeWideSnifferService(options *config.KsniffSettings, service kube.KubernetesApiService, bridge runtime.ContainerRuntimeBridge) SnifferService {
	return &NodeWideSnifferService{settings: options, privilegedContainerName: "ksniff-privileged", kubernetesApiService: service, runtimeBridge: bridge}
}

func (n *NodeWideSnifferService) Setup() error {
	var err error

	log.Infof("creating privileged pod for node-wide sniffing on node: '%s'", n.settings.DetectedPodNodeName)

	if n.settings.UseDefaultImage {
		n.settings.Image = n.runtimeBridge.GetDefaultImage()
	}

	if n.settings.UseDefaultTCPDumpImage {
		n.settings.TCPDumpImage = n.runtimeBridge.GetDefaultTCPImage()
	}

	if n.settings.UseDefaultSocketPath {
		n.settings.SocketPath = n.runtimeBridge.GetDefaultSocketPath()
	}

	n.privilegedPod, err = n.kubernetesApiService.CreatePrivilegedPod(
		n.settings.DetectedPodNodeName, n.privilegedContainerName, n.settings.Image, n.settings.SocketPath,
		n.settings.UserSpecifiedPodCreateTimeout, n.settings.UserSpecifiedServiceAccount)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", n.settings.DetectedPodNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", n.privilegedPod.Name, n.settings.DetectedPodNodeName)
	return nil
}

func (n *NodeWideSnifferService) Cleanup() error {
	command := n.runtimeBridge.BuildCleanupCommand()

	if command != nil {
		log.Infof("removing privileged container: '%s'", n.privilegedContainerName)
		exitCode, err := n.kubernetesApiService.ExecuteCommand(n.privilegedPod.Name, n.privilegedContainerName, command, &kube.NopWriter{})
		if err != nil {
			log.WithError(err).Errorf("failed to remove privileged container: '%s', exit code: '%d', "+
				"please manually remove it", n.privilegedContainerName, exitCode)
		} else {
			log.Infof("privileged container: '%s' removed successfully", n.privilegedContainerName)
		}
	}

	log.Infof("removing privileged pod: '%s'", n.privilegedPod.Name)
	err := n.kubernetesApiService.DeletePod(n.privilegedPod.Name)
	if err != nil {
		log.WithError(err).Errorf("failed to remove privileged pod: '%s', please manually remove it", n.privilegedPod.Name)
		return err
	}

	log.Infof("privileged pod: '%s' removed successfully", n.privilegedPod.Name)
	return nil
}

func (n *NodeWideSnifferService) Start(stdOut io.Writer) error {
	log.Info("starting node-wide sniffing using privileged pod")

	command := n.runtimeBridge.BuildNodeWideTcpdumpCommand(
		n.settings.UserSpecifiedInterface, n.settings.UserSpecifiedFilter, n.settings.SocketPath, n.settings.TCPDumpImage)

	exitCode, err := n.kubernetesApiService.ExecuteCommand(n.privilegedPod.Name, n.privilegedContainerName, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start node-wide sniffing using privileged pod, exit code: '%d'", exitCode)
		return err
	}

	log.Info("node-wide sniffing using privileged pod completed")
	return nil
}
