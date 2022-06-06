//go:build linux
// +build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestSandboxRemoveWithoutIPLeakage(t *testing.T) {
	const hostLocalCheckpointDir = "/var/lib/cni"

	t.Logf("Make sure host-local ipam is in use")
	config, err := CRIConfig()
	require.NoError(t, err)
	fs, err := os.ReadDir(config.NetworkPluginConfDir)
	require.NoError(t, err)
	require.NotEmpty(t, fs)
	f := filepath.Join(config.NetworkPluginConfDir, fs[0].Name())
	cniConfig, err := os.ReadFile(f)
	require.NoError(t, err)
	if !strings.Contains(string(cniConfig), "host-local") {
		t.Skip("host-local ipam is not in use")
	}

	t.Logf("Create a sandbox")
	sbConfig := PodSandboxConfig("sandbox", "remove-without-ip-leakage")
	sb, err := runtimeService.RunPodSandbox(sbConfig, *runtimeHandler)
	require.NoError(t, err)
	defer func() {
		// Make sure the sandbox is cleaned up in any case.
		runtimeService.StopPodSandbox(sb)
		runtimeService.RemovePodSandbox(sb)
	}()

	t.Logf("Get pod information")
	status, info, err := SandboxInfo(sb)
	require.NoError(t, err)
	ip := status.GetNetwork().GetIp()
	require.NotEmpty(t, ip)
	require.NotNil(t, info.RuntimeSpec.Linux)
	var netNS string
	for _, n := range info.RuntimeSpec.Linux.Namespaces {
		if n.Type == runtimespec.NetworkNamespace {
			netNS = n.Path
		}
	}
	require.NotEmpty(t, netNS, "network namespace should be set")

	t.Logf("Should be able to find the pod ip in host-local checkpoint")
	checkIP := func(ip string) bool {
		found := false
		filepath.Walk(hostLocalCheckpointDir, func(_ string, info os.FileInfo, _ error) error {
			if info != nil && info.Name() == ip {
				found = true
			}
			return nil
		})
		return found
	}
	require.True(t, checkIP(ip))

	t.Logf("Kill sandbox container")
	require.NoError(t, KillPid(int(info.Pid)))

	t.Logf("Unmount network namespace")
	require.NoError(t, unix.Unmount(netNS, unix.MNT_DETACH))

	t.Logf("Network namespace should be closed")
	_, info, err = SandboxInfo(sb)
	require.NoError(t, err)
	assert.True(t, info.NetNSClosed)

	t.Logf("Remove network namespace")
	require.NoError(t, os.RemoveAll(netNS))

	t.Logf("Network namespace should still be closed")
	_, info, err = SandboxInfo(sb)
	require.NoError(t, err)
	assert.True(t, info.NetNSClosed)

	t.Logf("Sandbox state should be NOTREADY")
	assert.NoError(t, Eventually(func() (bool, error) {
		status, err := runtimeService.PodSandboxStatus(sb)
		if err != nil {
			return false, err
		}
		return status.GetState() == runtime.PodSandboxState_SANDBOX_NOTREADY, nil
	}, time.Second, 30*time.Second), "sandbox state should become NOTREADY")

	t.Logf("Should still be able to find the pod ip in host-local checkpoint")
	assert.True(t, checkIP(ip))

	t.Logf("Should be able to stop and remove the sandbox")
	assert.NoError(t, runtimeService.StopPodSandbox(sb))
	assert.NoError(t, runtimeService.RemovePodSandbox(sb))

	t.Logf("Should not be able to find the pod ip in host-local checkpoint")
	assert.False(t, checkIP(ip))
}

// Issue: https://github.com/containerd/containerd/issues/5768
// PR: https://github.com/containerd/containerd/pull/5904
// This test simulates the network setup failure and teardown failure by renaming the name of portmap binary.
// Due to the nature of chained cni plugin, host-local ipam should have allocated IP address.
// RunPodSandx should leave such sandbox in the metadata store to cleanup IP address later.
func TestNetworkTeardownFailureWithoutIPLeakage(t *testing.T) {

	t.Logf("Make sure host-local ipam and portmap are in use")
	config, err := CRIConfig()
	require.NoError(t, err)
	fs, err := os.ReadDir(config.NetworkPluginConfDir)
	require.NoError(t, err)
	require.NotEmpty(t, fs)
	f := filepath.Join(config.NetworkPluginConfDir, fs[0].Name())
	cniConfig, err := os.ReadFile(f)
	require.NoError(t, err)
	if !strings.Contains(string(cniConfig), "host-local") {
		t.Skip("host-local ipam is not in use")
	}
	if !strings.Contains(string(cniConfig), "portmap") {
		t.Skip("portmap is not in use")
	}

	t.Logf("Rename the portmap binary")
	portmapBin := filepath.Join(config.NetworkPluginBinDir, "portmap")
	err = os.Rename(portmapBin, portmapBin+"_tmp")
	require.NoError(t, err)

	t.Logf("Count the numbers of IPs allocated currently")
	const ipDirPath = "/var/lib/cni/networks/containerd-net"
	ipDir, err := os.ReadDir(ipDirPath)
	require.NoError(t, err)
	originalIps := len(ipDir)

	t.Logf("Create a sandbox")
	const sandboxName = "sandbox-teardown"

	defer func() {
		// Change the portmap binary
		os.Rename(portmapBin+"_tmp", portmapBin)

		// Make sure the sandbox is cleaned up in any case.
		sandboxes, _ := ListSandbox()
		for _, sandbox := range sandboxes {
			if sandbox.Metadata.Name == sandboxName {
				runtimeService.StopPodSandbox(sandbox.Id)
				runtimeService.RemovePodSandbox(sandbox.Id)
			}
		}
	}()

	sbConfig := PodSandboxConfig(sandboxName, "teardown-failure-without-ip-leakage")
	// The returned sandbox id is empty in error cases
	_, err = runtimeService.RunPodSandbox(sbConfig, *runtimeHandler)
	require.Error(t, err)

	// Ensure the failure is due to plugin binary is not found
	require.Contains(t, err.Error(), "failed to setup network for sandbox")
	require.Contains(t, err.Error(), "failed to find plugin")

	t.Logf("Get pod information")
	sandboxes, err := ListSandbox()
	require.NoError(t, err)

	var sandboxID string
	for _, sandbox := range sandboxes {
		if sandbox.Metadata.Name == sandboxName {
			sandboxID = sandbox.Id
		}
	}
	require.NotEmpty(t, sandboxID, "sandboxId should be found")

	// sandbox status has no IP information when networkSetup fails
	sb, info, err := SandboxInfo(sandboxID)
	require.NoError(t, err)
	assert.Equal(t, runtime.PodSandboxState_SANDBOX_NOTREADY, sb.State)

	require.NotNil(t, info.RuntimeSpec.Linux)
	var netNS string
	for _, n := range info.RuntimeSpec.Linux.Namespaces {
		if n.Type == runtimespec.NetworkNamespace {
			netNS = n.Path
		}
	}
	require.NotEmpty(t, netNS, "network namespace should be set")

	t.Logf("Count the numbers of IPs allocated after teardown failure")
	ipDir, err = os.ReadDir(ipDirPath)
	require.NoError(t, err)
	// New IPv4 and IPv6 are allocated
	assert.Equal(t, originalIps+2, len(ipDir))

	err = os.Rename(portmapBin+"_tmp", portmapBin)
	require.NoError(t, err)

	t.Logf("Should be able to stop and remove the sandbox")
	assert.NoError(t, runtimeService.StopPodSandbox(sandboxID))
	assert.NoError(t, runtimeService.RemovePodSandbox(sandboxID))

	t.Logf("Count the numbers of IPs allocated after removing the sandbox")
	ipDir, err = os.ReadDir(ipDirPath)
	require.NoError(t, err)
	assert.Equal(t, originalIps, len(ipDir))
}
