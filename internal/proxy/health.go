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
// independent proof for the managed listener, TUN, VPN upstream and durable
// network-state transaction. An unfinished recovery journal blocks healthy.
func (m *Manager) Health() HealthSnapshot {
	mode := m.Mode()
	h := HealthSnapshot{
		State:      HealthIdle,
		Mode:       mode,
		Dimensions: make(map[string]HealthDimension),
		UpdatedAt:  time.Now().UTC(),
	}

	journal := m.NetworkJournalStatus()
	journalOK := !journal.Open || (mode == ModeAgentTunnel && journal.Phase == "active")
	h.Dimensions["network_journal"] = HealthDimension{OK: journalOK, Detail: journal.Detail}

	managed := m.ManagedRunning()
	h.Dimensions["managed_process"] = HealthDimension{OK: managed, Detail: managedProcessDetail(m.ManagedPID())}
	if mode == ModeOff || !managed {
		if journal.Open {
			h.State = HealthDegraded
		}
		return h
	}

	listenerReachable := m.Running()
	h.Dimensions["listener_reachable"] = HealthDimension{OK: listenerReachable, Detail: listenerReachabilityDetail(listenerReachable)}
	owned, listenerDetail := m.ManagedListenerOwned()
	m.mu.Lock()
	readinessConfirmed := m.proxyReadinessConfirmed
	m.mu.Unlock()
	h.Dimensions["mixed_listener_owned"] = HealthDimension{OK: owned, Detail: listenerDetail}

	if mode == ModeProxy {
		if listenerReachable && readinessConfirmed && !journal.Open {
			h.State = HealthHealthy
		} else {
			h.State = HealthDegraded
		}
		return h
	}

	tunOK := false
	tunDetail := agentTunName + " not present"
	if iface, err := net.InterfaceByName(agentTunName); err == nil {
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

	if owned && tunOK && vpnOK && journalOK {
		h.State = HealthHealthy
	} else {
		h.State = HealthDegraded
	}
	return h
}

func listenerReachabilityDetail(ok bool) string {
	if ok {
		return "configured local proxy listener accepts TCP connections"
	}
	return "configured local proxy listener is not reachable"
}

func managedProcessDetail(pid int) string {
	if pid <= 0 {
		return "no managed PID"
	}
	return "managed PID is running"
}
