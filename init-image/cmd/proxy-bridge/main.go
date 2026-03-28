// proxy-bridge runs at the VM level (outside the container namespace).
// It waits for /run/proxy.sock (created by vminitd's vsock relay),
// then bridges TCP 127.0.0.1:3128 <-> UDS /run/proxy.sock.
package main

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	proxySocketPath = "/run/proxy.sock"
	// Port must match ProxyManager.proxyPort in the Swift host code.
	listenAddr = "127.0.0.1:3128"
	pollTimeout     = 60 * time.Second
	pollInterval    = 100 * time.Millisecond
)

func waitForSocket(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		info, err := os.Stat(path)
		if err == nil && info.Mode().Type() == os.ModeSocket {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

// closeWrite is implemented by both net.TCPConn and net.UnixConn.
type halfCloser interface {
	CloseWrite() error
}

func relay(dst, src net.Conn) {
	io.Copy(dst, src)
	// Half-close the write side so the other direction can finish reading.
	if hc, ok := dst.(halfCloser); ok {
		hc.CloseWrite()
	} else {
		dst.Close()
	}
}

func handleConn(tcpConn net.Conn) {
	udsConn, err := net.Dial("unix", proxySocketPath)
	if err != nil {
		tcpConn.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); relay(udsConn, tcpConn) }()
	go func() { defer wg.Done(); relay(tcpConn, udsConn) }()
	wg.Wait()
	tcpConn.Close()
	udsConn.Close()
}

func main() {
	if !waitForSocket(proxySocketPath, pollTimeout) {
		os.Stderr.WriteString("proxy-bridge: timeout waiting for " + proxySocketPath + "\n")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		os.Stderr.WriteString("proxy-bridge: listen failed: " + err.Error() + "\n")
		os.Exit(1)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}
