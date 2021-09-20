package sniffer

import (
	"io"

	"ksniff/kube"
	"ksniff/pkg/config"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

var defaultInterface = "any"

type NodeSnifferService struct {
	*config.NodeSnifferServiceConfig
	privilegedPod           *v1.Pod
	privilegedContainerName string
	targetInterface         string
	// TODO Replace Node Name
	nodeName                string
	kubernetesApiService    kube.KubernetesApiService
}

func NewNodeSnifferService(options *config.KsniffSettings, service kube.KubernetesApiService) SnifferService {
	nodeSnifferService := &NodeSnifferService{
		NodeSnifferServiceConfig: &config.NodeSnifferServiceConfig{
			Image: options.UserSpecifiedImage,
			UserSpecifiedInterface: options.UserSpecifiedInterface,
			UserSpecifiedFilter: options.UserSpecifiedFilter,
			NodeName: options.UserSpecifiedNodeName,
			UserSpecifiedPodCreateTimeout: options.UserSpecifiedPodCreateTimeout,
		}, 
		privilegedContainerName: "node-sniff", 
		kubernetesApiService: service, 
		nodeName: options.DetectedPodNodeName, 
		targetInterface: defaultInterface,
	}

	if options.UseDefaultImage {
		nodeSnifferService.Image = "maintained/tcpdump"
	}

	return nodeSnifferService
}

func (nss *NodeSnifferService) Setup() error {
	var err error
	// TODO Create a Nodesniffer Object
	log.Infof("creating privileged pod on node: '%s'", nss.nodeName)
	log.Debugf("initiating sniff on node with option: '%v'", nss)
	
	podConfig := kube.PrivilegedPodConfig{
		// TODO Replace DetectedPodNodeName with PodName
		NodeName:      nss.nodeName,
		ContainerName: nss.privilegedContainerName,
		Image:         nss.Image,
		Timeout:       nss.UserSpecifiedPodCreateTimeout,
	}

	nss.privilegedPod, err = nss.kubernetesApiService.CreatePrivilegedPod(&podConfig)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", nss.nodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", nss.privilegedPod.Name, nss.nodeName)

	return nil
}

func (nss *NodeSnifferService) Cleanup() error {
	log.Infof("removing pod: '%s'", nss.privilegedPod.Name)

	err := nss.kubernetesApiService.DeletePod(nss.privilegedPod.Name)
	if err != nil {
		log.WithError(err).Errorf("failed to remove pod: '%s", nss.privilegedPod.Name)
		return err
	}

	log.Infof("pod: '%s' removed successfully", nss.privilegedPod.Name)

	return nil
}

func buildTcpdumpCommand(netInterface string, filter string, tcpdumpImage string) []string {
	return []string{"tcpdump", "-i", netInterface, "-U", "-w", "-", filter}
}

func (nss *NodeSnifferService) Start(stdOut io.Writer) error {
	log.Info("starting remote sniffing using privileged pod")

	command := buildTcpdumpCommand(nss.targetInterface, nss.UserSpecifiedFilter, nss.Image)

	exitCode, err := nss.kubernetesApiService.ExecuteCommand(nss.privilegedPod.Name, nss.privilegedContainerName, command, stdOut)
	if err != nil {
		log.WithError(err).Errorf("failed to start sniffing using privileged pod, exit code: '%d'", exitCode)
		return err
	}

	log.Info("remote sniffing using privileged pod completed")

	return nil
}
