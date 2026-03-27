// init-wrapper replaces /sbin/vminitd inside the custom init image.
// It starts proxy-bridge in the background, then execs the real vminitd
// so the VM boots normally with the proxy relay already running.
package main

import (
	"os"
	"syscall"
)

const (
	realVminitd = "/sbin/vminitd.real"
	proxyBridge = "/sbin/proxy-bridge"
)

func main() {
	// Start proxy-bridge as a background process.
	// It will poll for the proxy socket and begin relaying once available.
	attr := &syscall.ProcAttr{
		Env: os.Environ(),
		Files: []uintptr{
			uintptr(syscall.Stdin),
			uintptr(syscall.Stdout),
			uintptr(syscall.Stderr),
		},
	}
	_, err := syscall.ForkExec(proxyBridge, []string{proxyBridge}, attr)
	if err != nil {
		os.Stderr.WriteString("init-wrapper: failed to start proxy-bridge: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Exec the real vminitd, replacing this process.
	// Pass through all original arguments so vminitd sees the same CLI flags.
	err = syscall.Exec(realVminitd, append([]string{realVminitd}, os.Args[1:]...), os.Environ())
	// If we get here, exec failed.
	os.Stderr.WriteString("init-wrapper: exec vminitd.real failed: " + err.Error() + "\n")
	os.Exit(1)
}
