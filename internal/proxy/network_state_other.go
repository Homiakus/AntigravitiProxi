//go:build !linux && !windows

package proxy

import (
	"context"
	"fmt"
)

func capturePlatformNetworkSnapshot(context.Context) (NetworkSnapshot, error) {
	return emptySnapshot(), nil
}

func recoverPlatformOwnedNetworkState(context.Context, TunnelStateJournal) ([]string, error) {
	return nil, fmt.Errorf("automatic tunnel network-state recovery is unsupported on this platform")
}

func platformProcessAlive(int) bool { return false }
