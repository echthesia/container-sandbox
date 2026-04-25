// sandbox-init is the container init wrapper. It starts proxy-bridge
// immediately so the agent's network access is available as fast as possible,
// then in parallel forks dockerd (when /usr/bin/dockerd is installed) and a
// background watcher that detects docker0's actual IP and writes
// /home/sandbox/.docker/config.json. On SIGTERM/SIGINT it terminates
// proxy-bridge first, then gives dockerd a graceful shutdown window so it can
// flush state to /var/lib/docker before the container is torn down.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const (
	dockerdPath        = "/usr/bin/dockerd"
	dockerdLogPath     = "/var/log/dockerd.log"
	dockerSocketPath   = "/var/run/docker.sock"
	proxyBridgePath    = "/opt/sandbox/proxy-bridge"
	proxyBridgeLogPath = "/var/log/proxy-bridge.log"
	sandboxInitLogPath = "/var/log/sandbox-init.log"

	dockerBridgeIface    = "docker0"
	userDockerConfigDir  = "/home/sandbox/.docker"
	userDockerConfigPath = "/home/sandbox/.docker/config.json"

	dockerSocketWaitTimeout = 60 * time.Second
	bridgeWatchInterval     = 1 * time.Second
	gracefulShutdown        = 10 * time.Second
)

func main() {
	if log, err := os.OpenFile(sandboxInitLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		os.Stdout = log
		os.Stderr = log
	}
	os.Exit(run())
}

func run() int {
	// proxy-bridge first: agents can't talk to anything off-host without it,
	// and it has no dependency on dockerd.
	proxy := exec.Command(proxyBridgePath, os.Args[1:]...)
	if log, err := os.OpenFile(proxyBridgeLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		proxy.Stdout = log
		proxy.Stderr = log
	} else {
		proxy.Stdout = os.Stdout
		proxy.Stderr = os.Stderr
	}
	if err := proxy.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-init: proxy-bridge failed to start: %v\n", err)
		return 1
	}
	proxyExit := make(chan error, 1)
	go func() { proxyExit <- proxy.Wait() }()

	// dockerd in parallel; the bridge IP is detected and the user docker
	// config is overwritten asynchronously when docker0 actually appears.
	dockerd, dockerdExit := startDockerdIfPresent()
	if dockerd != nil {
		go finalizeNestedProxyConfig()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigCh:
		// proxy-bridge has no state; tell it to exit, then give dockerd time to flush.
		if proxy.Process != nil {
			_ = proxy.Process.Signal(syscall.SIGTERM)
		}
		<-proxyExit
		terminate(dockerd, dockerdExit)
	case <-proxyExit:
		// proxy-bridge exited on its own — bring dockerd down with it.
		terminate(dockerd, dockerdExit)
	}

	if proxy.ProcessState != nil {
		return proxy.ProcessState.ExitCode()
	}
	return 0
}

func startDockerdIfPresent() (*exec.Cmd, chan error) {
	if _, err := os.Stat(dockerdPath); err != nil {
		return nil, nil
	}

	logFile, err := os.OpenFile(dockerdLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-init: opening dockerd log failed: %v\n", err)
		return nil, nil
	}

	cmd := exec.Command(dockerdPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-init: dockerd failed to start: %v\n", err)
		logFile.Close()
		return nil, nil
	}

	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
		logFile.Close()
	}()
	return cmd, exitCh
}

// finalizeNestedProxyConfig waits for dockerd's bridge interface to come up
// (it's created lazily on first nested container in modern Docker), then
// overwrites the user docker config with the actual IP and subnet so docker
// auto-injects accurate proxy env into nested containers.
//
// Polls indefinitely; the goroutine dies when sandbox-init exits.
// The Containerfile-baked default at 172.17.0.1 covers the meantime.
func finalizeNestedProxyConfig() {
	socketDeadline := time.Now().Add(dockerSocketWaitTimeout)
	for time.Now().Before(socketDeadline) {
		if info, err := os.Stat(dockerSocketPath); err == nil && info.Mode().Type() == os.ModeSocket {
			fmt.Fprintf(os.Stdout, "sandbox-init: docker socket up\n")
			break
		}
		time.Sleep(bridgeWatchInterval)
	}

	for {
		ip, subnet, err := readDockerBridge()
		if err == nil {
			if writeErr := writeUserDockerConfig(ip, subnet); writeErr != nil {
				fmt.Fprintf(os.Stderr, "sandbox-init: write user docker config: %v\n", writeErr)
				return
			}
			fmt.Fprintf(os.Stdout, "sandbox-init: nested-proxy config written for %s (%s)\n", ip, subnet)
			return
		}
		time.Sleep(bridgeWatchInterval)
	}
}

func writeUserDockerConfig(ip, subnet string) error {
	if err := os.MkdirAll(userDockerConfigDir, 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf(`{
  "proxies": {
    "default": {
      "httpProxy": "http://%s:3128",
      "httpsProxy": "http://%s:3128",
      "noProxy": "localhost,127.0.0.1,::1,%s"
    }
  }
}
`, ip, ip, subnet)
	return os.WriteFile(userDockerConfigPath, []byte(body), 0o644)
}

func readDockerBridge() (ip, subnet string, err error) {
	iface, err := net.InterfaceByName(dockerBridgeIface)
	if err != nil {
		return "", "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		network := ip4.Mask(ipNet.Mask)
		return ip4.String(), fmt.Sprintf("%s/%d", network, ones), nil
	}
	return "", "", errors.New("no IPv4 on " + dockerBridgeIface)
}

func terminate(cmd *exec.Cmd, exitCh chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exitCh:
	case <-time.After(gracefulShutdown):
		_ = cmd.Process.Kill()
		<-exitCh
	}
}
