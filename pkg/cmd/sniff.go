package cmd

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	"ksniff/kube"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

var (
	ksniffExample = "kubectl sniff hello-minikube-7c77b68cff-qbvsd -c hello-minikube"
)

const minimumNumberOfArguments = 1
const tcpdumpBinaryName = "static-tcpdump"
const tcpdumpRemotePath = "/tmp/static-tcpdump"

var tcpdumpLocalBinaryPathLookupList []string

type SniffOptions struct {
	configFlags                    *genericclioptions.ConfigFlags
	resultingContext               *api.Context
	userSpecifiedPodName           string
	podNodeName                    string
	userSpecifiedInterface         string
	userSpecifiedFilter            string
	userSpecifiedContainer         string
	userSpecifiedNamespace         string
	userSpecifiedOutputFile        string
	userSpecifiedLocalTcpdumpPath  string
	userSpecifiedRemoteTcpdumpPath string
	userSpecifiedVerboseMode       bool
	userSpecifiedPrivilegedMode    bool
	containerId                    string
	clientset                      *kubernetes.Clientset
	restConfig                     *rest.Config
	rawConfig                      api.Config
	remoteSniffingService          RemoteSniffingService
	genericclioptions.IOStreams
}

func NewSniffOptions(streams genericclioptions.IOStreams) *SniffOptions {
	return &SniffOptions{
		configFlags: genericclioptions.NewConfigFlags(),

		IOStreams: streams,
	}
}

func NewCmdSniff(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewSniffOptions(streams)

	cmd := &cobra.Command{
		Use:          "sniff pod [-n namespace] [-c container] [-f filter] [-o output-file] [-l local-tcpdump-path] [-r remote-tcpdump-path]",
		Short:        "Perform network sniffing on a container running in a kubernetes cluster.",
		Example:      ksniffExample,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(c, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := o.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&o.userSpecifiedNamespace, "namespace", "n", "default", "namespace (optional)")
	_ = viper.BindEnv("namespace", "KUBECTL_PLUGINS_CURRENT_NAMESPACE")
	_ = viper.BindPFlag("namespace", cmd.Flags().Lookup("namespace"))

	cmd.Flags().StringVarP(&o.userSpecifiedInterface, "interface", "i", "any", "pod interface to packet capture (optional)")
	_ = viper.BindEnv("interface", "KUBECTL_PLUGINS_LOCAL_FLAG_INTERFACE")
	_ = viper.BindPFlag("interface", cmd.Flags().Lookup("interface"))

	cmd.Flags().StringVarP(&o.userSpecifiedContainer, "container", "c", "", "container (optional)")
	_ = viper.BindEnv("container", "KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER")
	_ = viper.BindPFlag("container", cmd.Flags().Lookup("container"))

	cmd.Flags().StringVarP(&o.userSpecifiedFilter, "filter", "f", "", "tcpdump filter (optional)")
	_ = viper.BindEnv("filter", "KUBECTL_PLUGINS_LOCAL_FLAG_FILTER")
	_ = viper.BindPFlag("filter", cmd.Flags().Lookup("filter"))

	cmd.Flags().StringVarP(&o.userSpecifiedOutputFile, "output-file", "o", "",
		"output file path, tcpdump output will be redirect to this file instead of wireshark (optional)")
	_ = viper.BindEnv("output-file", "KUBECTL_PLUGINS_LOCAL_FLAG_OUTPUT_FILE")
	_ = viper.BindPFlag("output-file", cmd.Flags().Lookup("output-file"))

	cmd.Flags().StringVarP(&o.userSpecifiedLocalTcpdumpPath, "local-tcpdump-path", "l", "",
		"local static tcpdump binary path (optional)")
	_ = viper.BindEnv("local-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_LOCAL_TCPDUMP_PATH")
	_ = viper.BindPFlag("local-tcpdump-path", cmd.Flags().Lookup("local-tcpdump-path"))

	cmd.Flags().StringVarP(&o.userSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", tcpdumpRemotePath,
		"remote static tcpdump binary path (optional)")
	_ = viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	_ = viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	cmd.Flags().BoolVarP(&o.userSpecifiedVerboseMode, "verbose", "v", false,
		"if specified, ksniff output will include debug information (optional)")
	_ = viper.BindEnv("verbose", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	_ = viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))

	cmd.Flags().BoolVarP(&o.userSpecifiedVerboseMode, "privileged", "p", false,
		"if specified, ksniff will deploy another pod that execute docker to execute into target pod as root")
	_ = viper.BindEnv("privileged", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	_ = viper.BindPFlag("privileged", cmd.Flags().Lookup("privileged"))

	return cmd
}

func (o *SniffOptions) Complete(cmd *cobra.Command, args []string) error {

	if len(args) < minimumNumberOfArguments {
		_ = cmd.Usage()
		return errors.New("not enough arguments")
	}

	o.userSpecifiedPodName = args[0]
	if o.userSpecifiedPodName == "" {
		return errors.New("pod name is empty")
	}

	o.userSpecifiedNamespace = viper.GetString("namespace")
	o.userSpecifiedContainer = viper.GetString("container")
	o.userSpecifiedInterface = viper.GetString("interface")
	o.userSpecifiedFilter = viper.GetString("filter")
	o.userSpecifiedOutputFile = viper.GetString("output-file")
	o.userSpecifiedLocalTcpdumpPath = viper.GetString("local-tcpdump-path")
	o.userSpecifiedRemoteTcpdumpPath = viper.GetString("remote-tcpdump-path")
	o.userSpecifiedVerboseMode = viper.GetBool("verbose")
	o.userSpecifiedPrivilegedMode = viper.GetBool("privileged")

	var err error

	if o.userSpecifiedVerboseMode {
		log.Info("running in verbose mode")
		log.SetLevel(log.DebugLevel)
	}

	tcpdumpLocalBinaryPathLookupList, err = o.buildTcpdumpBinaryPathLookupList()
	if err != nil {
		return err
	}

	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	o.restConfig, err = o.configFlags.ToRESTConfig()
	if err != nil {
		return err
	}

	o.restConfig.Timeout = 30 * time.Second

	o.clientset, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return err
	}

	currentContext, exists := o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	if !exists {
		return errors.New("context doesn't exist")
	}

	o.resultingContext = currentContext.DeepCopy()
	o.resultingContext.Namespace = o.userSpecifiedNamespace

	kubernetesApiService := kube.NewKubernetesApiService(o.clientset, o.restConfig, o.userSpecifiedNamespace)

	if o.userSpecifiedPrivilegedMode {
		log.Info("sniffing method: privileged pod")
		o.remoteSniffingService = NewPrivilegedPodRemoteSniffingService(o, kubernetesApiService)
	} else {
		log.Info("sniffing method: upload static tcpdump")
		o.remoteSniffingService = NewUploadTcpdumpRemoteSniffingService(o, kubernetesApiService)
	}

	return nil
}

func (o *SniffOptions) buildTcpdumpBinaryPathLookupList() ([]string, error) {
	userHomeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	ksniffBinaryPath, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		return nil, err
	}

	ksniffBinaryDir := filepath.Dir(ksniffBinaryPath)
	ksniffBinaryPath = filepath.Join(ksniffBinaryDir, tcpdumpBinaryName)

	kubeKsniffPluginFolder := filepath.Join(userHomeDir, filepath.FromSlash("/.kube/plugin/sniff/"), tcpdumpBinaryName)

	return append([]string{o.userSpecifiedLocalTcpdumpPath, ksniffBinaryPath},
		filepath.Join("/usr/local/bin/", tcpdumpBinaryName), kubeKsniffPluginFolder), nil
}

func (o *SniffOptions) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errors.New("context doesn't exist")
	}

	if o.userSpecifiedNamespace == "" {
		return errors.New("namespace value is empty should be custom or default")
	}

	var err error

	o.userSpecifiedLocalTcpdumpPath, err = findLocalTcpdumpBinaryPath()
	if err != nil {
		return err
	}

	log.Infof("using tcpdump path at: '%s'", o.userSpecifiedLocalTcpdumpPath)

	pod, err := o.clientset.CoreV1().Pods(o.userSpecifiedNamespace).Get(o.userSpecifiedPodName, v1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return errors.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	o.podNodeName = pod.Spec.NodeName

	log.Debugf("pod '%s' status: '%s'", o.userSpecifiedPodName, pod.Status.Phase)

	if len(pod.Spec.Containers) < 1 {
		return errors.New("no containers in specified pod")
	}

	if o.userSpecifiedContainer == "" {
		log.Info("no container specified, taking first container we found in pod.")
		o.userSpecifiedContainer = pod.Spec.Containers[0].Name
		log.Infof("selected container: '%s'", o.userSpecifiedContainer)
	}

	var containerFoundInPod = false
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if o.userSpecifiedContainer == containerStatus.Name {
			o.containerId = strings.TrimPrefix(containerStatus.ContainerID, "docker://")
			containerFoundInPod = true
			break
		}
	}

	if !containerFoundInPod {
		return errors.Errorf("couldn't find container: '%s' in pod: '%s'", o.userSpecifiedContainer, o.userSpecifiedPodName)
	}

	return nil
}

func findLocalTcpdumpBinaryPath() (string, error) {
	log.Debugf("searching for tcpdump binary using lookup list: '%v'", tcpdumpLocalBinaryPathLookupList)

	for _, possibleTcpdumpPath := range tcpdumpLocalBinaryPathLookupList {
		if _, err := os.Stat(possibleTcpdumpPath); err == nil {
			log.Debugf("tcpdump binary found at: '%s'", possibleTcpdumpPath)

			return possibleTcpdumpPath, nil
		}

		log.Debugf("tcpdump binary was not found at: '%s'", possibleTcpdumpPath)
	}

	return "", errors.Errorf("couldn't find static tcpdump binary on any of: '%v'", tcpdumpLocalBinaryPathLookupList)
}

func (o *SniffOptions) Run() error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s', interface: '%s']",
		o.userSpecifiedPodName, o.userSpecifiedNamespace, o.userSpecifiedContainer, o.userSpecifiedFilter, o.userSpecifiedInterface)

	err := o.remoteSniffingService.Setup()
	if err != nil {
		return err
	}

	defer func() {
		log.Info("starting sniffer cleanup")

		err := o.remoteSniffingService.Cleanup()
		if err != nil {
			log.WithError(err).Error("failed to teardown sniffer, a manual teardown is required.")
			return
		}

		log.Info("sniffer cleanup completed successfully")
	}()

	if o.userSpecifiedOutputFile != "" {
		log.Infof("output file option specified, storing output in: '%s'", o.userSpecifiedOutputFile)

		fileWriter, err := os.Create(o.userSpecifiedOutputFile)
		if err != nil {
			return err
		}

		err = o.remoteSniffingService.Start(fileWriter)
		if err != nil {
			return err
		}

	} else {
		log.Info("spawning wireshark!")

		title := fmt.Sprintf("gui.window_title:%s/%s/%s", o.userSpecifiedNamespace, o.userSpecifiedPodName, o.userSpecifiedContainer)
		cmd := exec.Command("wireshark", "-k", "-i", "-", "-o", title)

		stdinWriter, err := cmd.StdinPipe()
		if err != nil {
			return err
		}

		go func() {
			err := o.remoteSniffingService.Start(stdinWriter)
			if err != nil {
				log.WithError(err).Errorf("failed to start remote sniffing, stopping wireshark")
				_ = cmd.Process.Kill()
			}
		}()

		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}
