//go:build linux

// egress-probe is a tiny CI-only network client used to prove Linux
// process_name/process_path/domain routing. It intentionally does not read
// proxy environment variables; the connection must be steered by TUN policy.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: egress-probe URL [http-host]")
		os.Exit(2)
	}

	comm, _ := os.ReadFile("/proc/self/comm")
	fmt.Fprintf(os.Stderr, "pid=%d comm=%q exe=%q\n", os.Getpid(), strings.TrimSpace(string(comm)), mustExe())

	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: -1,
		}).DialContext,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
	req, err := http.NewRequest(http.MethodGet, os.Args[1], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(os.Args) == 3 {
		host := strings.TrimSpace(os.Args[2])
		if host == "" {
			fmt.Fprintln(os.Stderr, "http-host must not be empty")
			os.Exit(2)
		}
		req.Host = host
		fmt.Fprintf(os.Stderr, "http_host=%q\n", host)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, resp.Status)
		os.Exit(1)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(strings.TrimSpace(string(b)))
}

func mustExe() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}
