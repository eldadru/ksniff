package e2e

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func (t *TcpdumpUploadMethodE2ESuite) SetupSuite() {
	var err error

	t.targetPodResourcePath, err = filepath.Abs("../e2e/resources/nginx-deployment.yml")
	require.NoError(t.T(), err)

	t.kubectlOptions = k8s.NewKubectlOptions("", "")

	namespaceName := fmt.Sprintf("kubernetes-basic-example-%s", strings.ToLower(random.UniqueId()))
	k8s.CreateNamespace(t.T(), t.kubectlOptions, namespaceName)
	t.kubectlOptions.Namespace = namespaceName

	k8s.KubectlApply(t.T(), t.kubectlOptions, t.targetPodResourcePath)

	time.Sleep(10 * time.Second)
	t.pods = k8s.ListPods(t.T(), t.kubectlOptions, metav1.ListOptions{IncludeUninitialized: true})
	assert.Len(t.T(), t.pods, 1)

	t.targetPodName = t.pods[0].Name

	err = k8s.WaitUntilPodAvailableE(t.T(), t.kubectlOptions, t.targetPodName, 100, 100*time.Millisecond)
	assert.NoError(t.T(), err)
}

func (t *TcpdumpUploadMethodE2ESuite) TearDownSuite() {
	k8s.DeleteNamespace(t.T(), t.kubectlOptions, t.kubectlOptions.Namespace)
	k8s.KubectlDelete(t.T(), t.kubectlOptions, t.targetPodResourcePath)
}

func (t *TcpdumpUploadMethodE2ESuite) TestTcpdumpUploadMethod() {
	// given
	k8s.WaitUntilPodAvailable(t.T(), t.kubectlOptions, t.targetPodName, 100, 100*time.Millisecond)

	service := k8s.GetService(t.T(), t.kubectlOptions, "nginx-service")
	require.Equal(t.T(), service.Name, "nginx-service")

	cmd := exec.Command("kubectl", "sniff", t.targetPodName, "--namespace", t.kubectlOptions.Namespace, "-o", "/tmp/pod.pcap")

	// when
	output, err := runAndWaitForOutput(cmd, "output file option specified", 20*time.Second)
	assert.NoError(t.T(), err, "timeout while waiting for desired output: "+output)

	// then
	time.Sleep(300 * time.Millisecond)

	_, err = http.Post(fmt.Sprintf("http://127.0.0.1:%d/testing", service.Spec.Ports[0].NodePort), "text/plain", strings.NewReader("e2e-testing"))
	assert.NoError(t.T(), err)

	time.Sleep(1 * time.Second)

	if err := cmd.Process.Kill(); err != nil {
		assert.Fail(t.T(), "failed to kill process")
	}

	verifyPcapContains(t.T(), "/tmp/pod.pcap", "e2e-testing")
}

func (t *TcpdumpUploadMethodE2ESuite) TestPrivilegedModeMethod() {
	// given
	k8s.WaitUntilPodAvailable(t.T(), t.kubectlOptions, t.targetPodName, 100, 100*time.Millisecond)

	service := k8s.GetService(t.T(), t.kubectlOptions, "nginx-service")
	require.Equal(t.T(), service.Name, "nginx-service")

	cmd := exec.Command("kubectl", "sniff", t.targetPodName, "--namespace", t.kubectlOptions.Namespace, "-p", "-o", "/tmp/pod.pcap")

	// when
	output, err := runAndWaitForOutput(cmd, "starting remote sniffing using privileged pod", 20*time.Second)
	assert.NoError(t.T(), err, "timeout while waiting for desired output: "+output)

	// then
	time.Sleep(3000 * time.Millisecond)

	_, err = http.Post(fmt.Sprintf("http://127.0.0.1:%d/testing", service.Spec.Ports[0].NodePort), "text/plain", strings.NewReader("e2e-testing"))
	assert.NoError(t.T(), err)

	time.Sleep(1 * time.Second)

	if err := cmd.Process.Kill(); err != nil {
		assert.Fail(t.T(), "failed to kill process")
	}

	verifyPcapContains(t.T(), "/tmp/pod.pcap", "e2e-testing")
}

func verifyPcapContains(t *testing.T, pcapPath string, shouldContain string) {
	if handle, err := pcap.OpenOffline(pcapPath); err != nil {
		assert.NoError(t, err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if bytes.Contains(packet.Data(), []byte(shouldContain)) {
				return
			}
		}

		assert.Fail(t, "couldn't find our packet inside the pcap output.")
	}
}

func runAndWaitForOutput(cmd *exec.Cmd, desiredOutput string, timeout time.Duration) (string, error) {
	var allOutput []string

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	err = cmd.Start()
	if err != nil {
		return "", nil
	}

	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)

	wg := &sync.WaitGroup{}
	mutex := &sync.Mutex{}
	outputFound := make(chan struct{})

	wg.Add(2)
	go readTillOutputFound(stdoutScanner, wg, mutex, &allOutput, desiredOutput, outputFound)
	go readTillOutputFound(stderrScanner, wg, mutex, &allOutput, desiredOutput, outputFound)

	err = WaitForOutput(wg, outputFound, timeout)
	if err != nil {
		return strings.Join(allOutput, "\n"), err
	}

	if err := stdoutScanner.Err(); err != nil {
		return "", err
	}

	if err := stderrScanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(allOutput, "\n"), nil
}

func WaitForOutput(wg *sync.WaitGroup, outputFound chan struct{}, timeout time.Duration) error {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-outputFound:
		return nil
	case <-c:
		return errors.New("completed before output found")
	case <-time.After(timeout):
		return errors.New("timed out before output found")
	}
}

func readTillOutputFound(scanner *bufio.Scanner, wg *sync.WaitGroup, mutex *sync.Mutex, allOutput *[]string, desiredOutput string, outputFound chan struct{}) {
	defer wg.Done()
	for scanner.Scan() {
		mutex.Lock()
		text := scanner.Text()
		*allOutput = append(*allOutput, text)
		mutex.Unlock()

		if strings.Contains(text, desiredOutput) {
			close(outputFound)
			return
		}
	}
}

type TcpdumpUploadMethodE2ESuite struct {
	suite.Suite
	pods                  []corev1.Pod
	targetPodName         string
	kubectlOptions        *k8s.KubectlOptions
	targetPodResourcePath string
}

func TestTcpdumpUploadMethodE2ESuite(t *testing.T) {
	suite.Run(t, new(TcpdumpUploadMethodE2ESuite))
}
