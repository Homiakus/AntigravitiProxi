//go:build !linux

package proxy

func validateAgentTunnelHost(binary string) error { return nil }
