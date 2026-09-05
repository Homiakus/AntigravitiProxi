package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
)

const (
	networkStateSchema = 1
	agentTunName       = "antigravity-tun"
)

type NetworkSnapshot struct {
	CapturedAt          time.Time `json:"captured_at"`
	Platform            string    `json:"platform"`
	RoutesV4            []string  `json:"routes_v4,omitempty"`
	RoutesV6            []string  `json:"routes_v6,omitempty"`
	RulesV4             []string  `json:"rules_v4,omitempty"`
	RulesV6             []string  `json:"rules_v6,omitempty"`
	DNSFingerprint      string    `json:"dns_fingerprint,omitempty"`
	FirewallFingerprint string    `json:"firewall_fingerprint,omitempty"`
}

type OwnedNetworkDelta struct {
	TunnelInterface     string   `json:"tunnel_interface,omitempty"`
	NewRouteTablesV4    []string `json:"new_route_tables_v4,omitempty"`
	NewRouteTablesV6    []string `json:"new_route_tables_v6,omitempty"`
	NewRulePrioritiesV4 []int    `json:"new_rule_priorities_v4,omitempty"`
	NewRulePrioritiesV6 []int    `json:"new_rule_priorities_v6,omitempty"`
	DNSChanged          bool     `json:"dns_changed"`
	FirewallChanged     bool     `json:"firewall_changed"`
}

type TunnelStateJournal struct {
	SchemaVersion int               `json:"schema_version"`
	Phase         string            `json:"phase"`
	OperationID   string            `json:"operation_id"`
	PID           int               `json:"pid,omitempty"`
	PIDIdentity   string            `json:"pid_identity,omitempty"`
	VPNInterface  string            `json:"vpn_interface"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Before        NetworkSnapshot   `json:"before"`
	Active        *NetworkSnapshot  `json:"active,omitempty"`
	Owned         OwnedNetworkDelta `json:"owned"`
	LastError     string            `json:"last_error,omitempty"`
	Recovery      []string          `json:"recovery,omitempty"`

	// RecoveredFromPreviousGood is runtime-only evidence. It prevents a corrupt
	// primary journal from overwriting the validated backup on the first repair
	// write and is intentionally never persisted.
	RecoveredFromPreviousGood bool `json:"-"`
}

type NetworkJournalStatus struct {
	Open        bool      `json:"open"`
	Phase       string    `json:"phase,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	Detail      string    `json:"detail"`
}

func (m *Manager) networkJournalPath() string {
	return filepath.Join(m.Config().Root, "network-state.json")
}

func (m *Manager) networkJournalPreviousGoodPath() string {
	return m.networkJournalPath() + ".previous-good"
}

func (m *Manager) lastCleanNetworkJournalPath() string {
	return filepath.Join(m.Config().Root, "network-state-last-clean.json")
}

func decodeTunnelJournal(b []byte) (*TunnelStateJournal, error) {
	var j TunnelStateJournal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if j.SchemaVersion != networkStateSchema {
		return nil, fmt.Errorf("unsupported schema %d", j.SchemaVersion)
	}
	if strings.TrimSpace(j.OperationID) == "" {
		return nil, errors.New("missing operation_id")
	}
	switch j.Phase {
	case "prepared", "active", "recovering", "clean", "aborted-before-network-apply":
	default:
		return nil, fmt.Errorf("unsupported phase %q", j.Phase)
	}
	return &j, nil
}

func (m *Manager) loadTunnelJournal() (*TunnelStateJournal, error) {
	path := m.networkJournalPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j, primaryErr := decodeTunnelJournal(b)
	if primaryErr == nil {
		return j, nil
	}

	// Atomic writes keep the immediately preceding complete value. It is safe
	// to use only if it validates structurally and is not the already-finalized
	// operation recorded as last-clean. beginTunnelTransaction also removes any
	// previous operation's leftover backup before writing a new prepared state.
	backupRaw, backupReadErr := os.ReadFile(m.networkJournalPreviousGoodPath())
	if backupReadErr != nil {
		return nil, fmt.Errorf("network-state journal invalid: %v; previous-good unavailable: %w", primaryErr, backupReadErr)
	}
	backup, backupErr := decodeTunnelJournal(backupRaw)
	if backupErr != nil {
		return nil, fmt.Errorf("network-state journal invalid: %v; previous-good invalid: %v", primaryErr, backupErr)
	}
	if cleanRaw, cleanErr := os.ReadFile(m.lastCleanNetworkJournalPath()); cleanErr == nil {
		if clean, decodeErr := decodeTunnelJournal(cleanRaw); decodeErr == nil && clean.OperationID == backup.OperationID {
			return nil, fmt.Errorf("network-state journal invalid: %v; previous-good belongs to already-clean operation %s", primaryErr, backup.OperationID)
		}
	}
	backup.RecoveredFromPreviousGood = true
	backup.LastError = appendJournalError(backup.LastError, "primary network-state journal invalid; recovered previous-good: "+primaryErr.Error())
	return backup, nil
}

func appendJournalError(existing, next string) string {
	if strings.TrimSpace(existing) == "" {
		return next
	}
	return existing + "; " + next
}

func (m *Manager) writeTunnelJournal(j *TunnelStateJournal) error {
	j.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(m.networkJournalPath(), append(b, '\n'), 0o600)
}

func (m *Manager) beginTunnelTransaction(ctx context.Context) error {
	if err := m.RecoverStaleNetworkState(ctx); err != nil {
		return fmt.Errorf("stale network-state recovery: %w", err)
	}
	if _, err := net.InterfaceByName(agentTunName); err == nil {
		return fmt.Errorf("refusing Agent Tunnel start: unowned %s already exists", agentTunName)
	}
	before, err := capturePlatformNetworkSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("capture pre-tunnel network state: %w", err)
	}
	if err := preflightPlatformNetworkOwnership(before); err != nil {
		return fmt.Errorf("network ownership preflight: %w", err)
	}

	// A previous operation's backup must never become a candidate for this new
	// operation. The new primary prepared journal is atomic, so there is no need
	// for an older-operation previous-good before the first state transition.
	if err := os.Remove(m.networkJournalPreviousGoodPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale previous-good journal: %w", err)
	}

	now := time.Now().UTC()
	j := &TunnelStateJournal{
		SchemaVersion: networkStateSchema,
		Phase:         "prepared",
		OperationID:   fmt.Sprintf("%d-%d", now.UnixNano(), os.Getpid()),
		VPNInterface:  m.Config().VPNInterface,
		CreatedAt:     now,
		UpdatedAt:     now,
		Before:        before,
		Owned:         reservedPlatformOwnership(),
	}
	return m.writeTunnelJournal(j)
}

func (m *Manager) markTunnelActive(ctx context.Context) error {
	j, err := m.loadTunnelJournal()
	if err != nil {
		return err
	}
	if j == nil {
		return errors.New("network-state journal missing during Agent Tunnel activation")
	}
	active, err := capturePlatformNetworkSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("capture active tunnel network state: %w", err)
	}
	j.Phase = "active"
	j.PID = m.ManagedPID()
	if j.PID > 0 {
		identity, identityErr := platformProcessIdentity(j.PID)
		if identityErr != nil {
			return fmt.Errorf("capture managed process identity: %w", identityErr)
		}
		j.PIDIdentity = identity
	}
	j.Active = &active
	j.Owned = mergeOwnedNetworkDelta(j.Owned, deriveOwnedNetworkDelta(j.Before, active))
	j.Owned.TunnelInterface = agentTunName
	return m.writeTunnelJournal(j)
}

func (m *Manager) abortPreparedTunnelTransaction(reason string) {
	j, err := m.loadTunnelJournal()
	if err != nil || j == nil || j.Phase != "prepared" || m.ManagedRunning() {
		return
	}
	j.LastError = reason
	j.Phase = "aborted-before-network-apply"
	_ = m.persistCleanJournal(j)
}

func (m *Manager) persistCleanJournal(j *TunnelStateJournal) error {
	j.UpdatedAt = time.Now().UTC()
	j.RecoveredFromPreviousGood = false
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(m.lastCleanNetworkJournalPath(), append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Remove(m.networkJournalPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(m.networkJournalPreviousGoodPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m *Manager) quarantineInvalidPrimary(j *TunnelStateJournal) error {
	if !j.RecoveredFromPreviousGood {
		return nil
	}
	path := m.networkJournalPath()
	quarantine := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Rename(path, quarantine); err != nil {
		return fmt.Errorf("quarantine invalid primary journal: %w", err)
	}
	j.Recovery = append(j.Recovery, "quarantined invalid primary journal as "+filepath.Base(quarantine))
	j.RecoveredFromPreviousGood = false
	return nil
}

// RecoverStaleNetworkState is deliberately conservative. Linux first reserves
// and preflights an explicit iproute2 table/rule namespace before any mutation;
// the journal therefore already knows what may be cleaned even if the process
// dies before active evidence is persisted. Observed before/after differences
// are merged only as additional evidence. Unknown TUNs or live previous helper
// PIDs always fail closed. If the primary journal is corrupt, a validated
// previous-good from the same non-clean operation is quarantined/replayed before
// any network mutation.
func (m *Manager) RecoverStaleNetworkState(ctx context.Context) error {
	j, err := m.loadTunnelJournal()
	if err != nil {
		return err
	}
	if j == nil {
		return nil
	}
	if j.Phase == "clean" || j.Phase == "aborted-before-network-apply" {
		return m.persistCleanJournal(j)
	}
	if j.PID > 0 && platformProcessAlive(j.PID) {
		identity, identityErr := platformProcessIdentity(j.PID)
		if j.PIDIdentity == "" || identityErr != nil {
			return fmt.Errorf("previous Agent Tunnel journal still points to live PID %d without verifiable process identity; refusing to mutate its network state", j.PID)
		}
		if identity == j.PIDIdentity {
			return fmt.Errorf("previous Agent Tunnel journal still points to the same live PID %d; refusing to mutate its network state", j.PID)
		}
		j.Recovery = append(j.Recovery, fmt.Sprintf("PID %d was reused by a different process identity; stale helper ownership released", j.PID))
	}

	current, err := capturePlatformNetworkSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("capture stale network state: %w", err)
	}
	if j.Active == nil {
		j.Owned = mergeOwnedNetworkDelta(j.Owned, deriveOwnedNetworkDelta(j.Before, current))
		j.Owned.TunnelInterface = agentTunName
	}
	if err := m.quarantineInvalidPrimary(j); err != nil {
		return err
	}
	j.Phase = "recovering"
	if err := m.writeTunnelJournal(j); err != nil {
		return err
	}

	actions, err := recoverPlatformOwnedNetworkState(ctx, *j)
	if err != nil {
		privilegedActions, privilegedErr := m.tryPrivilegedNetworkRecovery(ctx, err)
		if privilegedErr == nil {
			actions = append(actions, privilegedActions...)
			err = nil
		} else if privilegedErr != err {
			err = fmt.Errorf("unprivileged recovery: %v; privileged recovery: %w", err, privilegedErr)
		}
	}
	if err != nil {
		j.LastError = err.Error()
		j.Recovery = append(j.Recovery, actions...)
		_ = m.writeTunnelJournal(j)
		return err
	}
	j.Recovery = append(j.Recovery, actions...)

	post, err := capturePlatformNetworkSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("capture post-recovery network state: %w", err)
	}
	if err := verifyOwnedDeltaAbsent(post, j.Owned); err != nil {
		j.LastError = err.Error()
		_ = m.writeTunnelJournal(j)
		return err
	}
	if _, err := net.InterfaceByName(agentTunName); err == nil {
		return fmt.Errorf("recovery incomplete: %s still exists", agentTunName)
	}
	j.Phase = "clean"
	j.PID = 0
	j.PIDIdentity = ""
	j.LastError = ""
	return m.persistCleanJournal(j)
}

func (m *Manager) finishTunnelTransaction(ctx context.Context) error {
	j, err := m.loadTunnelJournal()
	if err != nil || j == nil {
		return err
	}
	if m.ManagedRunning() {
		return errors.New("cannot finalize network-state journal while managed sing-box is still running")
	}
	return m.RecoverStaleNetworkState(ctx)
}

func (m *Manager) NetworkJournalStatus() NetworkJournalStatus {
	j, err := m.loadTunnelJournal()
	if err != nil {
		return NetworkJournalStatus{Open: true, Phase: "invalid", Detail: err.Error()}
	}
	if j == nil {
		return NetworkJournalStatus{Detail: "no open network transaction"}
	}
	detail := "network-state transaction requires completion or recovery"
	if j.RecoveredFromPreviousGood {
		detail = "primary journal is invalid; validated previous-good is available for recovery"
	}
	return NetworkJournalStatus{
		Open:        true,
		Phase:       j.Phase,
		OperationID: j.OperationID,
		UpdatedAt:   j.UpdatedAt,
		Detail:      detail,
	}
}

func deriveOwnedNetworkDelta(before, after NetworkSnapshot) OwnedNetworkDelta {
	return OwnedNetworkDelta{
		TunnelInterface:     agentTunName,
		NewRouteTablesV4:    newRouteTables(before.RoutesV4, after.RoutesV4),
		NewRouteTablesV6:    newRouteTables(before.RoutesV6, after.RoutesV6),
		NewRulePrioritiesV4: newRulePriorities(before.RulesV4, after.RulesV4),
		NewRulePrioritiesV6: newRulePriorities(before.RulesV6, after.RulesV6),
		DNSChanged:          before.DNSFingerprint != "" && after.DNSFingerprint != "" && before.DNSFingerprint != after.DNSFingerprint,
		FirewallChanged:     before.FirewallFingerprint != "" && after.FirewallFingerprint != "" && before.FirewallFingerprint != after.FirewallFingerprint,
	}
}

func newRouteTables(before, after []string) []string {
	b := map[string]bool{}
	for _, line := range before {
		if t := routeTable(line); t != "" {
			b[t] = true
		}
	}
	seen := map[string]bool{}
	for _, line := range after {
		if t := routeTable(line); t != "" && !b[t] {
			seen[t] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func routeTable(line string) string {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "table" {
			return f[i+1]
		}
	}
	return ""
}

func newRulePriorities(before, after []string) []int {
	b := map[int]bool{}
	for _, line := range before {
		if p, ok := rulePriority(line); ok {
			b[p] = true
		}
	}
	seen := map[int]bool{}
	for _, line := range after {
		if p, ok := rulePriority(line); ok && !b[p] {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func rulePriority(line string) (int, bool) {
	first := strings.Fields(strings.TrimSpace(line))
	if len(first) == 0 {
		return 0, false
	}
	s := strings.TrimSuffix(first[0], ":")
	p, err := strconv.Atoi(s)
	return p, err == nil
}

func verifyOwnedDeltaAbsent(post NetworkSnapshot, owned OwnedNetworkDelta) error {
	for _, t := range owned.NewRouteTablesV4 {
		for _, line := range post.RoutesV4 {
			if routeTable(line) == t {
				return fmt.Errorf("owned IPv4 route table %s remains after recovery", t)
			}
		}
	}
	for _, t := range owned.NewRouteTablesV6 {
		for _, line := range post.RoutesV6 {
			if routeTable(line) == t {
				return fmt.Errorf("owned IPv6 route table %s remains after recovery", t)
			}
		}
	}
	for _, p := range owned.NewRulePrioritiesV4 {
		for _, line := range post.RulesV4 {
			if got, ok := rulePriority(line); ok && got == p {
				return fmt.Errorf("owned IPv4 rule priority %d remains after recovery", p)
			}
		}
	}
	for _, p := range owned.NewRulePrioritiesV6 {
		for _, line := range post.RulesV6 {
			if got, ok := rulePriority(line); ok && got == p {
				return fmt.Errorf("owned IPv6 rule priority %d remains after recovery", p)
			}
		}
	}
	return nil
}

func normalizedLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func emptySnapshot() NetworkSnapshot {
	return NetworkSnapshot{CapturedAt: time.Now().UTC(), Platform: runtime.GOOS}
}
