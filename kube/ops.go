package kube

import (
	"bytes"
	"io"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
)

type KubeRequest struct {
	Clientset  *kubernetes.Clientset
	RestConfig *rest.Config
	Namespace  string
	Pod        string
	Container  string
}

type ExecCommandRequest struct {
	KubeRequest
	Command []string
	StdIn   io.Reader
	StdOut  io.Writer
	StdErr  io.Writer
}

type UploadFileRequest struct {
	KubeRequest
	Src string
	Dst string
}

func (w *NopWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

type NopWriter struct {
}

func (w *Writer) Write(p []byte) (n int, err error) {
	str := string(p)
	if len(str) > 0 {
		w.Output += str
	}
	return len(str), nil
}

type Writer struct {
	Output string
}

func PodUploadFile(req UploadFileRequest) (int, error) {
	stdOut := new(NopWriter)
	stdErr := new(NopWriter)

	fileContent, err := ioutil.ReadFile(req.Src)
	if err != nil {
		return 0, err
	}

	tarFile, err := WrapAsTar(req.Dst, fileContent)
	if err != nil {
		return 0, err
	}

	stdIn := bytes.NewReader(tarFile)

	execTarRequest := ExecCommandRequest{
		KubeRequest: KubeRequest{
			Clientset:  req.Clientset,
			RestConfig: req.RestConfig,
			Namespace:  req.Namespace,
			Pod:        req.Pod,
			Container:  req.Container,
		},
		Command: []string{"tar", "-xf", "-"},
		StdIn:   stdIn,
		StdOut:  stdOut,
		StdErr:  stdErr,
	}

	return PodExecuteCommand(execTarRequest)
}

func PodExecuteCommand(req ExecCommandRequest) (int, error) {
	execRequest := req.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(req.Pod).
		Namespace(req.Namespace).
		SubResource("exec")

	execRequest.VersionedParams(&corev1.PodExecOptions{
		Container: req.Container,
		Command:   req.Command,
		Stdin:     req.StdIn != nil,
		Stdout:    req.StdOut != nil,
		Stderr:    req.StdErr != nil,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(req.RestConfig, "POST", execRequest.URL())
	if err != nil {
		return 0, err
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  req.StdIn,
		Stdout: req.StdOut,
		Stderr: req.StdErr,
		Tty:    false,
	})

	var exitCode = 0

	if err != nil {
		if exitErr, ok := err.(utilexec.ExitError); ok && exitErr.Exited() {
			exitCode = exitErr.ExitStatus()
			err = nil
		}
	}

	return exitCode, err
}
