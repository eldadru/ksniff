package cmd

import (
	"context"
	"fmt"
	"io"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var (
	ksniffExample = "kubectl sniff hello-minikube-7c77b68cff-qbvsd -c hello-minikube"
)

const minimumNumberOfArguments = 1
const tcpdumpBinaryName = "static-tcpdump"
const tcpdumpRemotePath = "/tmp/static-tcpdump"

var tcpdumpLocalBinaryPathLookupList []string

type Ksniff struct {
	configFlags      *genericclioptions.ConfigFlags
	resultingContext *api.Context
	clientset        *kubernetes.Clientset
	restConfig       *rest.Config
	rawConfig        api.Config
	settings         *config.KsniffSettings
	snifferServices  []sniffer.SnifferService
}

func NewKsniff(settings *config.KsniffSettings) *Ksniff {
	return &Ksniff{settings: settings, configFlags: genericclioptions.NewConfigFlags(true)}
}

func NewCmdSniff(streams genericclioptions.IOStreams) *cobra.Command {
	ksniffSettings := config.NewKsniffSettings(streams)

	ksniff := NewKsniff(ksniffSettings)

	cmd := &cobra.Command{
		Use:          "sniff pod [-n namespace] [-c container] [-f filter] [-o output-file] [-l local-tcpdump-path] [-r remote-tcpdump-path]",
		Short:        "Perform network sniffing on a container running in a kubernetes cluster.",
		Example:      ksniffExample,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := ksniff.Complete(c, args); err != nil {
				return err
			}
			if err := ksniff.Validate(); err != nil {
				return err
			}
			if err := ksniff.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedNamespace, "namespace", "n", "", "namespace (optional)")
	_ = viper.BindEnv("namespace", "KUBECTL_PLUGINS_CURRENT_NAMESPACE")
	_ = viper.BindPFlag("namespace", cmd.Flags().Lookup("namespace"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedInterface, "interface", "i", "any", "pod interface to packet capture (optional)")
	_ = viper.BindEnv("interface", "KUBECTL_PLUGINS_LOCAL_FLAG_INTERFACE")
	_ = viper.BindPFlag("interface", cmd.Flags().Lookup("interface"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedContainer, "container", "c", "", "container (optional)")
	_ = viper.BindEnv("container", "KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER")
	_ = viper.BindPFlag("container", cmd.Flags().Lookup("container"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedFilter, "filter", "f", "", "tcpdump filter (optional)")
	_ = viper.BindEnv("filter", "KUBECTL_PLUGINS_LOCAL_FLAG_FILTER")
	_ = viper.BindPFlag("filter", cmd.Flags().Lookup("filter"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedOutputFile, "output-file", "o", "",
		"output file path, tcpdump output will be redirect to this file instead of wireshark (optional) ('-' stdout)")
	_ = viper.BindEnv("output-file", "KUBECTL_PLUGINS_LOCAL_FLAG_OUTPUT_FILE")
	_ = viper.BindPFlag("output-file", cmd.Flags().Lookup("output-file"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedLocalTcpdumpPath, "local-tcpdump-path", "l", "",
		"local static tcpdump binary path (optional)")
	_ = viper.BindEnv("local-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_LOCAL_TCPDUMP_PATH")
	_ = viper.BindPFlag("local-tcpdump-path", cmd.Flags().Lookup("local-tcpdump-path"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", tcpdumpRemotePath,
		"remote static tcpdump binary path (optional)")
	_ = viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	_ = viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	cmd.Flags().BoolVarP(&ksniffSettings.UserSpecifiedVerboseMode, "verbose", "v", false,
		"if specified, ksniff output will include debug information (optional)")
	_ = viper.BindEnv("verbose", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	_ = viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))

	cmd.Flags().BoolVarP(&ksniffSettings.UserSpecifiedPrivilegedMode, "privileged", "p", false,
		"if specified, ksniff will deploy another pod that have privileges to attach target pod network namespace")
	_ = viper.BindEnv("privileged", "KUBECTL_PLUGINS_LOCAL_FLAG_PRIVILEGED")
	_ = viper.BindPFlag("privileged", cmd.Flags().Lookup("privileged"))

	cmd.Flags().DurationVarP(&ksniffSettings.UserSpecifiedPodCreateTimeout, "pod-creation-timeout", "",
		1*time.Minute, "the length of time to wait for privileged pod to be created (e.g. 20s, 2m, 1h). "+
			"A value of zero means the creation never times out.")

	cmd.Flags().StringVarP(&ksniffSettings.Image, "image", "", "",
		"the privileged container image (optional)")
	_ = viper.BindEnv("image", "KUBECTL_PLUGINS_LOCAL_FLAG_IMAGE")
	_ = viper.BindPFlag("image", cmd.Flags().Lookup("image"))

	cmd.Flags().StringVarP(&ksniffSettings.TCPDumpImage, "tcpdump-image", "", "",
		"the tcpdump container image (optional)")
	_ = viper.BindEnv("tcpdump-image", "KUBECTL_PLUGINS_LOCAL_FLAG_TCPDUMP_IMAGE")
	_ = viper.BindPFlag("tcpdump-image", cmd.Flags().Lookup("tcpdump-image"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedKubeContext, "context", "x", "",
		"kubectl context to work on (optional)")
	_ = viper.BindEnv("context", "KUBECTL_PLUGINS_CURRENT_CONTEXT")
	_ = viper.BindPFlag("context", cmd.Flags().Lookup("context"))

	cmd.Flags().StringVarP(&ksniffSettings.SocketPath, "socket", "", "",
		"the container runtime socket path (optional)")
	_ = viper.BindEnv("socket", "KUBECTL_PLUGINS_SOCKET_PATH")
	_ = viper.BindPFlag("socket", cmd.Flags().Lookup("socket"))

	return cmd
}

func (o *Ksniff) Complete(cmd *cobra.Command, args []string) error {

	if len(args) < minimumNumberOfArguments {
		_ = cmd.Usage()
		return errors.New("not enough arguments")
	}

	o.settings.UserSpecifiedPodName = args[0]
	if o.settings.UserSpecifiedPodName == "" {
		return errors.New("pod name is empty")
	}

	o.settings.UserSpecifiedNamespace = viper.GetString("namespace")
	o.settings.UserSpecifiedContainer = viper.GetString("container")
	o.settings.UserSpecifiedInterface = viper.GetString("interface")
	o.settings.UserSpecifiedFilter = viper.GetString("filter")
	o.settings.UserSpecifiedOutputFile = viper.GetString("output-file")
	o.settings.UserSpecifiedLocalTcpdumpPath = viper.GetString("local-tcpdump-path")
	o.settings.UserSpecifiedRemoteTcpdumpPath = viper.GetString("remote-tcpdump-path")
	o.settings.UserSpecifiedVerboseMode = viper.GetBool("verbose")
	o.settings.UserSpecifiedPrivilegedMode = viper.GetBool("privileged")
	o.settings.UserSpecifiedKubeContext = viper.GetString("context")
	o.settings.UseDefaultImage = !cmd.Flag("image").Changed
	o.settings.UseDefaultTCPDumpImage = !cmd.Flag("tcpdump-image").Changed
	o.settings.UseDefaultSocketPath = !cmd.Flag("socket").Changed
	
	var err error

	if o.settings.UserSpecifiedVerboseMode {
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

	var currentContext *api.Context
	var exists bool

	if o.settings.UserSpecifiedKubeContext != "" {
		currentContext, exists = o.rawConfig.Contexts[o.settings.UserSpecifiedKubeContext]
	} else {
		currentContext, exists = o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	}

	if !exists {
		return errors.New("context doesn't exist")
	}

	o.restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: o.configFlags.ToRawKubeConfigLoader().ConfigAccess().GetDefaultFilename()},
		&clientcmd.ConfigOverrides{
			CurrentContext: o.settings.UserSpecifiedKubeContext,
		}).ClientConfig()

	if err != nil {
		return err
	}

	o.restConfig.Timeout = 30 * time.Second

	o.clientset, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return err
	}

	o.resultingContext = currentContext.DeepCopy()
	if o.settings.UserSpecifiedNamespace != "" {
		o.resultingContext.Namespace = o.settings.UserSpecifiedNamespace
	}

	return nil
}

func (o *Ksniff) buildTcpdumpBinaryPathLookupList() ([]string, error) {
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

	return append([]string{o.settings.UserSpecifiedLocalTcpdumpPath, ksniffBinaryPath},
		filepath.Join("/usr/local/bin/", tcpdumpBinaryName), kubeKsniffPluginFolder), nil
}
func (o *Ksniff) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errors.New("context doesn't exist")
	}

	if o.resultingContext.Namespace == "" {
		return errors.New("namespace value is empty should be custom or default")
	}

	var err error

	if !o.settings.UserSpecifiedPrivilegedMode {
		o.settings.UserSpecifiedLocalTcpdumpPath, err = findLocalTcpdumpBinaryPath()
		if err != nil {
			return err
		}

		log.Infof("using tcpdump path at: '%s'", o.settings.UserSpecifiedLocalTcpdumpPath)
	}

	pod, err := o.clientset.CoreV1().Pods(o.resultingContext.Namespace).Get(context.TODO(), o.settings.UserSpecifiedPodName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	snifferService, err := o.getPodSnifferService(pod)
	if err != nil {
		return err
	}
	o.snifferServices = append(o.snifferServices, snifferService)

	return nil
}

func (o *Ksniff) getPodSnifferService(pod *corev1.Pod) (sniffer.SnifferService, error) {
	// TODO ; Remove the dependence on o.settings

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return nil, errors.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	o.settings.DetectedPodNodeName = pod.Spec.NodeName

	log.Debugf("pod '%s' status: '%s'", o.settings.UserSpecifiedPodName, pod.Status.Phase)

	if len(pod.Spec.Containers) < 1 {
		return nil, errors.New("no containers in specified pod")
	}

	if o.settings.UserSpecifiedContainer == "" {
		log.Info("no container specified, taking first container we found in pod.")
		//TODO  Side affect for o.settings...
		o.settings.UserSpecifiedContainer = pod.Spec.Containers[0].Name
		log.Infof("selected container: '%s'", o.settings.UserSpecifiedContainer)
	}

	kubernetesApiService := kube.NewKubernetesApiService(o.clientset, o.restConfig, o.resultingContext.Namespace)

	// Get a Sniffer Service
	var snifferVar sniffer.SnifferService
	var err error

	if o.settings.UserSpecifiedPrivilegedMode {
		log.Info("sniffing method: privileged pod")
		snifferVar, err = sniffer.NewPrivilegedPodRemoteSniffingService(o.settings, pod, kubernetesApiService)
	} else if o.settings.UserSpecifiedNodeMode {
		log.Info("sniffing method: node")
		snifferVar = sniffer.NewNodeSnifferService(o.settings, kubernetesApiService)
	} else {
		log.Info("sniffing method: upload static tcpdump")
		snifferVar = sniffer.NewUploadTcpdumpRemoteSniffingService(o.settings, kubernetesApiService)
	}

	if err != nil || snifferVar == nil {
		log.Fatalf("Unable to build sniffer service for pod %v", pod)
		return nil, err
	}

	return snifferVar, nil
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

func (o *Ksniff) Run() error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s', interface: '%s']",
		o.settings.UserSpecifiedPodName, o.resultingContext.Namespace, o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedFilter, o.settings.UserSpecifiedInterface)

	for _, snifferService := range o.snifferServices {
		err := snifferService.Setup()

		if err != nil {
			return err
		}
	}

	defer func() {
		log.Info("starting sniffer cleanup")

		var errList []error

		for _, snifferService := range o.snifferServices {
			err := snifferService.Setup()
			errList = append(errList, err)
		}

		if len(errList) != 0 {
			for _, err := range errList {
				log.WithError(err).Error("failed to teardown sniffer, a manual teardown is required.")
			}
			// Failed to tear down some of the
			return
		}

		log.Info("sniffer cleanup completed successfully")
	}()

	
	// TODO If there are multiple Pods then an outputfile per Pod and create a folder
	if o.settings.UserSpecifiedOutputFile != "" {
		log.Infof("output file option specified, storing output in: '%s'", o.settings.UserSpecifiedOutputFile)

		var errList []error
		var err error
		var fileWriter io.Writer
		var fileWriters []io.Writer
		if len(o.snifferServices) > 1 {
			err = os.Mkdir("pcapcollection", 0775)
			if err != nil {
				log.Infof("Unable to create directory for the pcap collection. %v", err)
				return err
			}

			for index, _ := range o.snifferServices {
				// TODO Base this from the sniffer pod name
				fileWriter, err = os.Create(fmt.Sprintf("pcapcollection/sniffer-%d.pcap", index))
				if err != nil {
					log.Infof("Unable to create directory for the pcap collection. %v", err)
					return err
				}
				fileWriters = append(fileWriters, fileWriter)
			}

		} else if o.settings.UserSpecifiedOutputFile == "-" {
			fileWriter = os.Stdout
		} else {
			fileWriter, err = os.Create(o.settings.UserSpecifiedOutputFile)
			if err != nil {
				return err
			}
		}

		for id, snifferService := range o.snifferServices {
			err := snifferService.Start(fileWriters[id])
			errList = append(errList, err)
		}

		if len(errList) != 0 {
			for _, err := range errList {
				// TODO Add the resource that failed
				log.WithError(err).Error("failed to teardown sniffer, a manual teardown is required.")
			}
			// Failed to tear down some of the resources
			return errList[0]
		}
	} else {
		// TODO Add validation checks for multi-pods without selecting -o into the validate function (When multiple Pods is added to the CLI)
		if len(o.snifferServices) != 1 {
			return fmt.Errorf("unable to run wireshark when collecting from multiple resources. Resources %v", o.snifferServices)
			
		}

		log.Info("spawning wireshark!")
		title := fmt.Sprintf("gui.window_title:%s/%s/%s", o.resultingContext.Namespace, o.settings.UserSpecifiedPodName, o.settings.UserSpecifiedContainer)
		cmd := exec.Command("wireshark", "-k", "-i", "-", "-o", title)

		stdinWriter, err := cmd.StdinPipe()
		if err != nil {
			return err
		}

		go func() {
			// Using wireshark only supports a single collection
			err := o.snifferServices[0].Start(stdinWriter)
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
