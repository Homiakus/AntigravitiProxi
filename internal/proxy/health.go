package proxy

import (
	"net"
	"time"
)

type HealthState string

const (
	HealthIdle     HealthState = "idle"
	HealthHealthy  HealthState = "healthy"
	HealthDegraded HealthState = "degraded"
)

type HealthDimension struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type HealthSnapshot struct {
	State      HealthState                `json:"state"`
	Mode       Mode                       `json:"mode"`
	Dimensions map[string]HealthDimension `json:"dimensions"`
	UpdatedAt  time.Time                  `json:"updated_at"`
}

// Health is deliberately evidence-based. A reachable TCP port alone is never
// considered healthy because a foreign process may own it. Agent Tunnel needs
// three independent facts: the managed sing-box process owns the local mixed
// listener, the TUN interface is UP, and the configured VPN upstream is UP.
func (m *Manager) Health() HealthSnapshot {
	mode := m.Mode()
	h := HealthSnapshot{
		State:      HealthIdle,
		Mode:       mode,
		Dimensions: make(map[string]HealthDimension),
		UpdatedAt:  time.Now().UTC(),
	}

	managed := m.ManagedRunning()
	h.Dimensions["managed_process"] = HealthDimension{OK: managed, Detail: managedProcessDetail(m.ManagedPID())}
	if mode == ModeOff || !managed {
		return h
	}

	owned, listenerDetail := m.ManagedListenerOwned()
	h.Dimensions["mixed_listener_owned"] = HealthDimension{OK: owned, Detail: listenerDetail}

	if mode == ModeProxy {
		if owned {
			h.State = HealthHealthy
		} else {
			h.State = HealthDegraded
		}
		return h
	}

	tunOK := false
	tunDetail := "antigravity-tun not present"
	if iface, err := net.InterfaceByName("antigravity-tun"); err == nil {
		tunOK = iface.Flags&net.FlagUp != 0
		tunDetail = iface.Flags.String()
	}
	h.Dimensions["tun"] = HealthDimension{OK: tunOK, Detail: tunDetail}

	cfg := m.Config()
	vpnOK := false
	vpnDetail := "VPN interface not configured"
	if cfg.VPNInterface != "" {
		if iface, err := net.InterfaceByName(cfg.VPNInterface); err == nil {
			vpnOK = iface.Flags&net.FlagUp != 0
			vpnDetail = iface.Flags.String()
		} else {
			vpnDetail = err.Error()
		}
	}
	h.Dimensions["vpn_interface"] = HealthDimension{OK: vpnOK, Detail: vpnDetail}

	if owned && tunOK && vpnOK {
		h.State = HealthHealthy
	} else {
		h.State = HealthDegraded
	}
	return h
}

func managedProcessDetail(pid int) string {
	if pid <= 0 {
		return "no managed PID"
	}
	return "managed PID is running"
}
