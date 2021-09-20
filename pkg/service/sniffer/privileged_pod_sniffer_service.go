package sniffer

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer/runtime"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

type PrivilegedPodSnifferService struct {
	*config.PrivilegedSnifferServiceConfig
	privilegedPod           *corev1.Pod
	privilegedContainerName string
	targetProcessId         *string
	kubernetesApiService    kube.KubernetesApiService
	runtimeBridge           runtime.ContainerRuntimeBridge
}


func NewPrivilegedPodRemoteSniffingService(knsiffSettings *config.KsniffSettings, pod *corev1.Pod, service kube.KubernetesApiService) (SnifferService, error) {
	runtimeStr, containerID, err := getPodContainerRuntimeDetails(pod)

	if err != nil {
		return nil, err
	}

	bridge := runtime.NewContainerRuntimeBridge(runtimeStr)

	snifferService := &PrivilegedPodSnifferService{
		privilegedContainerName: "ksniff-privileged",
		kubernetesApiService:    service,
		runtimeBridge:           bridge,
		PrivilegedSnifferServiceConfig: &config.PrivilegedSnifferServiceConfig{
			DetectedContainerId:           containerID,
			DetectedContainerRuntime:      runtimeStr,
			Image:                         knsiffSettings.Image,
			TCPDumpImage:                  knsiffSettings.TCPDumpImage,
			SocketPath:                    knsiffSettings.SocketPath,
			DetectedPodNodeName:           knsiffSettings.DetectedPodNodeName,
			UserSpecifiedInterface:        knsiffSettings.UserSpecifiedInterface,
			UserSpecifiedFilter:           knsiffSettings.UserSpecifiedFilter,
			UserSpecifiedPodCreateTimeout: knsiffSettings.UserSpecifiedPodCreateTimeout,
		},
	}
	// Overwrite with defaults if not specified
	if knsiffSettings.UseDefaultImage {
		snifferService.Image = snifferService.runtimeBridge.GetDefaultImage()
	}

	if knsiffSettings.UseDefaultTCPDumpImage {
		snifferService.TCPDumpImage = snifferService.runtimeBridge.GetDefaultTCPImage()
	}

	if knsiffSettings.UseDefaultSocketPath {
		snifferService.SocketPath = snifferService.runtimeBridge.GetDefaultSocketPath()
	}
	

	return snifferService, nil

}

func (p *PrivilegedPodSnifferService) Setup() error {
	var err error

	log.Infof("creating privileged pod on node: '%s'", p.DetectedPodNodeName)

	podConfig := kube.PrivilegedPodConfig{
		NodeName:      p.DetectedPodNodeName,
		ContainerName: p.privilegedContainerName,
		Image:         p.Image,
		SocketPath:    p.SocketPath,
		Timeout:       p.UserSpecifiedPodCreateTimeout,
	}

	p.privilegedPod, err = p.kubernetesApiService.CreatePrivilegedPod(&podConfig)

	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", p.DetectedPodNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", p.privilegedPod.Name, p.DetectedPodNodeName)

	if p.runtimeBridge.NeedsPid() {
		var buff bytes.Buffer
		command := p.runtimeBridge.BuildInspectCommand(p.DetectedContainerId)
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
		&p.DetectedContainerId,
		p.UserSpecifiedInterface,
		p.UserSpecifiedFilter,
		p.targetProcessId,
		p.SocketPath,
		p.TCPDumpImage,
	)

	exitCode, err := p.kubernetesApiService.ExecuteCommand(p.privilegedPod.Name, p.privilegedContainerName, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
		return err
	}

	log.Info("remote sniffing using privileged pod completed")

	return nil
}

// Collect information about the container runtime that is running the Pod
func getPodContainerRuntimeDetails(pod *corev1.Pod) (containerRuntime string, containerID string, err error) {
	if len(pod.Spec.Containers) < 1 {
		return "", "", fmt.Errorf("the pod provided does not have any containers")
	}
	containerName := pod.Spec.Containers[0].Name

	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerName == containerStatus.Name {
			result := strings.Split(containerStatus.ContainerID, "://")
			if len(result) != 2 {
				break
			}
			containerRuntime = result[0]
			containerID = result[1]
			return
		}
	}
	err = errors.Errorf("couldn't find container: '%s' in pod: '%s'", containerName, pod.Name)
	return
}