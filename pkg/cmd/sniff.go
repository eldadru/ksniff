package cmd

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
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
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
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
	userSpecifiedPod               string
	userSpecifiedFilter            string
	userSpecifiedContainer         string
	userSpecifiedNamespace         string
	userSpecifiedOutputFile        string
	userSpecifiedLocalTcpdumpPath  string
	userSpecifiedRemoteTcpdumpPath string
	userSpecifiedVerboseMode       bool
	clientset                      *kubernetes.Clientset
	restConfig                     *rest.Config
	rawConfig                      api.Config
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
	viper.BindEnv("namespace", "KUBECTL_PLUGINS_CURRENT_NAMESPACE")
	viper.BindPFlag("namespace", cmd.Flags().Lookup("namespace"))

	cmd.Flags().StringVarP(&o.userSpecifiedContainer, "container", "c", "", "container (optional)")
	viper.BindEnv("container", "KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER")
	viper.BindPFlag("container", cmd.Flags().Lookup("container"))

	cmd.Flags().StringVarP(&o.userSpecifiedFilter, "filter", "f", "", "filter (optional)")
	viper.BindEnv("filter", "KUBECTL_PLUGINS_LOCAL_FLAG_FILTER")
	viper.BindPFlag("filter", cmd.Flags().Lookup("filter"))

	cmd.Flags().StringVarP(&o.userSpecifiedOutputFile, "output-file", "o", "", "output file path, tcpdump output will be redirect to this file instead of wireshark (optional)")
	viper.BindEnv("output-file", "KUBECTL_PLUGINS_LOCAL_FLAG_OUTPUT_FILE")
	viper.BindPFlag("output-file", cmd.Flags().Lookup("output-file"))

	cmd.Flags().StringVarP(&o.userSpecifiedLocalTcpdumpPath, "local-tcpdump-path", "l", "", "local static tcpdump binary path (optional)")
	viper.BindEnv("local-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_LOCAL_TCPDUMP_PATH")
	viper.BindPFlag("local-tcpdump-path", cmd.Flags().Lookup("local-tcpdump-path"))

	cmd.Flags().StringVarP(&o.userSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", tcpdumpRemotePath, "remote static tcpdump binary path (optional)")
	viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	cmd.Flags().BoolVarP(&o.userSpecifiedVerboseMode, "verbose", "v", false, "if specified, ksniff output will include debug information (optional)")
	viper.BindEnv("verbose", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))

	return cmd
}

func (o *SniffOptions) Complete(cmd *cobra.Command, args []string) error {

	if len(args) < minimumNumberOfArguments {
		cmd.Usage()
		return errors.New("not enough arguments")
	}

	o.userSpecifiedPod = args[0]
	if o.userSpecifiedPod == "" {
		return errors.New("pod name is empty")
	}

	o.userSpecifiedNamespace = viper.GetString("namespace")
	o.userSpecifiedContainer = viper.GetString("container")
	o.userSpecifiedFilter = viper.GetString("filter")
	o.userSpecifiedOutputFile = viper.GetString("output-file")
	o.userSpecifiedLocalTcpdumpPath = viper.GetString("local-tcpdump-path")
	o.userSpecifiedRemoteTcpdumpPath = viper.GetString("remote-tcpdump-path")
	o.userSpecifiedVerboseMode = viper.GetBool("verbose")

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

	pod, err := o.clientset.CoreV1().Pods(o.userSpecifiedNamespace).Get(o.userSpecifiedPod, v1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return errors.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	log.Debugf("pod '%s' status: '%s'", o.userSpecifiedPod, pod.Status.Phase)

	if len(pod.Spec.Containers) < 1 {
		return errors.New("no containers in specified pod")
	}

	if o.userSpecifiedContainer == "" {
		log.Info("no container specified, taking first container we found in pod.")
		o.userSpecifiedContainer = pod.Spec.Containers[0].Name
		log.Infof("selected container: '%s'", o.userSpecifiedContainer)
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

func CheckIfTcpdumpExistOnPod(o *SniffOptions, tcpdumpRemotePath string) (bool, error) {
	stdOut := new(kube.Writer)
	stdErr := new(kube.Writer)

	req := kube.ExecCommandRequest{
		KubeRequest: kube.KubeRequest{
			Clientset:  o.clientset,
			RestConfig: o.restConfig,
			Namespace:  o.userSpecifiedNamespace,
			Pod:        o.userSpecifiedPod,
			Container:  o.userSpecifiedContainer,
		},
		Command: []string{"/bin/sh", "-c", fmt.Sprintf("ls -alt %s", tcpdumpRemotePath)},
		StdOut:  stdOut,
		StdErr:  stdErr,
	}

	exitCode, err := kube.PodExecuteCommand(req)
	if err != nil {
		return false, err
	}

	log.Debugf("checked for tcpdump on remote pod: exit-code: '%d', stdout: '%s', stderr: '%s'",
		exitCode, stdOut.Output, stdErr.Output)

	if exitCode != 0 {
		return false, nil
	}

	if stdErr.Output != "" {
		return false, errors.New("failed to check for tcpdump")
	}

	log.Infof("static-tcpdump found: '%s'", stdOut.Output)

	return true, nil
}

func (o *SniffOptions) UploadTcpdumpIfMissing() error {
	log.Infof("checking for static tcpdump binary on: '%s'", o.userSpecifiedRemoteTcpdumpPath)

	isExist, err := CheckIfTcpdumpExistOnPod(o, o.userSpecifiedRemoteTcpdumpPath)
	if err != nil {
		return err
	}

	if isExist {
		log.Info("tcpdump was already on remote pod")
		return nil
	}

	log.Infof("couldn't find static tcpdump binary on: '%s', starting to upload", o.userSpecifiedRemoteTcpdumpPath)

	req := kube.UploadFileRequest{
		KubeRequest: kube.KubeRequest{
			Clientset:  o.clientset,
			RestConfig: o.restConfig,
			Namespace:  o.userSpecifiedNamespace,
			Pod:        o.userSpecifiedPod,
			Container:  o.userSpecifiedContainer,
		},
		Src: o.userSpecifiedLocalTcpdumpPath,
		Dst: o.userSpecifiedRemoteTcpdumpPath,
	}

	exitCode, err := kube.PodUploadFile(req)
	if err != nil || exitCode != 0 {
		return errors.Wrapf(err, "upload file command failed, exitCode: %d", exitCode)
	}

	log.Info("verifying tcpdump uploaded successfully")

	isExist, err = CheckIfTcpdumpExistOnPod(o, o.userSpecifiedRemoteTcpdumpPath)
	if err != nil {
		return err
	}

	if !isExist {
		log.Error("failed to upload tcpdump.")
		return errors.New("couldn't locate tcpdump on pod after upload done")
	}

	log.Info("tcpdump uploaded successfully")

	return nil
}

func (o *SniffOptions) ExecuteTcpdumpOnRemotePod(stdOut io.Writer) {

	log.Debugf("executing tcpdump on remote pod")

	stdErr := new(kube.Writer)

	executeTcpdumpRequest := kube.ExecCommandRequest{
		KubeRequest: kube.KubeRequest{
			Clientset:  o.clientset,
			RestConfig: o.restConfig,
			Namespace:  o.userSpecifiedNamespace,
			Pod:        o.userSpecifiedPod,
			Container:  o.userSpecifiedContainer,
		},
		Command: []string{o.userSpecifiedRemoteTcpdumpPath, "-U", "-w", "-", o.userSpecifiedFilter},
		StdErr:  stdErr,
		StdOut:  stdOut,
	}

	exitCode, err := kube.PodExecuteCommand(executeTcpdumpRequest)

	log.WithError(err).Debugf("tcpdump executed, exitCode: '%d', stdErr: '%s'", exitCode, stdErr)
}

func (o *SniffOptions) Run() error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s']",
		o.userSpecifiedPod, o.userSpecifiedNamespace, o.userSpecifiedContainer, o.userSpecifiedFilter)

	err := o.UploadTcpdumpIfMissing()
	if err != nil {
		return err
	}

	var outputWriter io.Writer

	if o.userSpecifiedOutputFile != "" {
		log.Infof("output file option specified, storing output in: '%s'", o.userSpecifiedOutputFile)

		f, err := os.Create(o.userSpecifiedOutputFile)
		if err != nil {
			return err
		}

		o.ExecuteTcpdumpOnRemotePod(f)

	} else {
		log.Info("spawning wireshark!", o.userSpecifiedOutputFile)

		cmd := exec.Command("wireshark", "-k", "-i", "-")

		outputWriter, err = cmd.StdinPipe()
		if err != nil {
			return err
		}

		go o.ExecuteTcpdumpOnRemotePod(outputWriter)

		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}
