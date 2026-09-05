package proxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const foreignListenerHelperEnv = "AGP_FOREIGN_LISTENER_HELPER"

// TestForeignListenerHelper is executed in a child copy of the current test
// binary. Keeping the listener in a different PID is essential: the parent can
// then prove that TCP reachability alone cannot satisfy managed-listener health.
func TestForeignListenerHelper(t *testing.T) {
	if os.Getenv(foreignListenerHelperEnv) != "1" {
		return
	}
	addr := os.Getenv("AGP_FOREIGN_LISTENER_ADDR")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "LISTEN_ERROR", err)
		os.Exit(2)
	}
	defer ln.Close()
	fmt.Fprintln(os.Stdout, "READY")

	for {
		conn, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		_ = conn.Close()
	}
}

func TestForeignListenerCannotBecomeHealthy(t *testing.T) {
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	cmd := exec.Command(os.Args[0], "-test.run=^TestForeignListenerHelper$")
	cmd.Env = append(os.Environ(),
		foreignListenerHelperEnv+"=1",
		"AGP_FOREIGN_LISTENER_ADDR="+addr,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	ready := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		if s.Scan() {
			ready <- s.Text()
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "READY" {
			t.Fatalf("foreign listener helper did not become ready: stdout=%q stderr=%q", line, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("foreign listener helper readiness timeout: %s", stderr.String())
	}

	// First establish the exact failure mode this test protects against: a plain
	// port probe succeeds even though the listener belongs to another process.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("foreign listener is not reachable: %v", err)
	}
	_ = conn.Close()

	m := New(Config{
		Root:        t.TempDir(),
		Host:        "127.0.0.1",
		Port:        port,
		DNSProvider: "cloudflare",
		SingBoxVer:  DefaultSingBoxVersion,
	}, nil)

	// Model a Manager that believes a different PID is its managed sing-box.
	// processOwnsTCPListener must reject the reachable helper listener because
	// socket ownership does not match this PID.
	m.mu.Lock()
	m.mode = ModeProxy
	m.cmd = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.mu.Unlock()

	owned, detail := m.ManagedListenerOwned()
	if owned {
		t.Fatalf("foreign listener incorrectly accepted as managed: %s", detail)
	}
	if !strings.Contains(strings.ToLower(detail), "not owned") {
		t.Fatalf("ownership rejection lacks actionable detail: %q", detail)
	}

	health := m.Health()
	if health.State != HealthDegraded {
		t.Fatalf("foreign reachable listener produced health=%q want=%q; %#v", health.State, HealthDegraded, health)
	}
	dim, ok := health.Dimensions["mixed_listener_owned"]
	if !ok {
		t.Fatalf("health omitted mixed_listener_owned evidence: %#v", health)
	}
	if dim.OK {
		t.Fatalf("foreign listener made ownership dimension healthy: %#v", dim)
	}
}
