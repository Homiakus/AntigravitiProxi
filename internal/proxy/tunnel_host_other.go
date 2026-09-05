//go:build !linux

package proxy

import (
	"context"
)

func validateAgentTunnelHost(binary string) error { return nil }

func tunnelUpstreamHostRoutes(ctx context.Context, vpn string) ([]string, error) { return nil, nil }

func (m *Manager) tryPrivilegedNetworkRecovery(ctx context.Context, cause error) ([]string, error) {
	return nil, cause
}
