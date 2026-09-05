# MASTER PLAN — AntigravitiProxi

## 0. Правила планирования и FMEA

Риски являются частью реализации. Источник истины — [`risks/register.json`](risks/register.json), методика — [`docs/ARCHITECTURE_FMEA.md`](docs/ARCHITECTURE_FMEA.md).

Обязательные правила:

- каждый незакрытый риск имеет `owner`, S/O/D, RPN, mitigation, verification и `target_milestone`;
- каждый незакрытый Risk ID обязан присутствовать в этом плане; `go run ./cmd/riskcheck` проверяет связность;
- `RPN >= 150` или `Severity >= 9` — release-significant;
- release tag обязан пройти `go run ./cmd/riskcheck -release`;
- high/critical риск перед release должен быть `closed` либо `accepted` с `acceptance_reason`;
- FMEA пересматривается после изменения TUN/routing/privilege model, инцидента и перед release;
- RPN снижается только после появления проверяемого control/evidence.

### Risk → plan index

| Risk | Основное действие |
|---|---|
| R-001 | P1 transactional startup/rollback + fault injection |
| R-002 | P1/P2 PID egress assurance + helper learning |
| R-003 | P1 visible isolation-relaxed; P2 learned policy |
| R-004 | P2 VPN lifecycle/rebind recovery |
| R-005 | P2/P4 IPv4/IPv6 + DNS + UDP/QUIC assurance |
| R-006 | P1 Linux fixed-function helper done; Windows minimal UAC helper |
| R-007 | P1 compatibility contract; P4 SBOM/provenance/signing |
| R-008 | Closed: enforced loopback-only invariant |
| R-009 | P1 hosts ownership + TTL |
| R-010 | P1 crash/orphan recovery + ownership token |
| R-011 | P2 backend/account-vs-transport classification |
| R-012 | P1 automatic Linux capability repair + upgrade fixture |
| R-013 | P1 route-conflict preflight; P4 Docker/VM/distro matrix |
| R-014 | P1 multidimensional health + explicit lifecycle states |
| R-015 | P1 runtime PID/socket/outbound/external-egress assurance |
| R-016 | P1 bounded shutdown + journal recovery |
| R-017 | P1 protect `main` with required checks |
| R-018 | P4 Linux ARM64 + distro runtime coverage |
| R-019 | P1 diagnostic redaction + Windows ACL evidence |
| R-020 | P2 dynamic backend endpoint discovery |
| R-021 | P1 UI/settings/runtime contract tests |
| R-022 | P1 managed listener/orphan ownership proof |
| R-023 | Closed: fail-closed privileged dependency digest |
| R-024 | P1 migrate remaining persistence writes to atomic helper |
| R-025 | P1 conservative route/rule recovery ownership |
| R-026 | P1 journal corruption/schema migration |
| R-027 | P1 Windows exact route ownership/recovery |

## 1. Каноническая архитектура, которую нельзя рассинхронизировать

### Transport ladder

```text
SAFE MODE
  process-only proxy env
        ↓
local mixed proxy
        ↓
selected VPN

AGENT TUNNEL
  Antigravity process/path
        ↓
  antigravity-tun
        ↓
  vpn-direct → selected VPN

unrelated traffic
        ↓
  system-direct

ELIGIBILITY DIAGNOSIS
  verified transport + authoritative backend reject
        ↓
  Agent Doctor / account-backend diagnosis
```

### Linux routing invariant

```text
auto_route=true
strict_route=true
auto_redirect=false
process/path rules BEFORE sniff
```

Этот профиль зафиксирован реальным dual-egress evidence. Возврат `auto_redirect=true` без нового runtime proof запрещён.

### Linux privilege invariant

```text
ordinary-user control plane
        ↓
explicit Agent Tunnel start
        ↓
TUN/capability readiness
        ↓ if missing
one fixed-function PolicyKit helper
        ↓
verify path/owner/SHA-256
        ↓
modprobe/libcap/setcap exact capabilities
        ↓
re-verify SHA-256 + capabilities
        ↓
ordinary-user control plane continues
```

Пароль не проходит через AntigravitiProxi. Helper не принимает arbitrary command.

### Assurance invariant

`ACTIVE` не равно `VERIFIED`.

```text
process tree → PID → socket/source endpoint → sing-box connection/outbound → external egress
```

Isolation выводится отдельно от route assurance. Domain fallback обязан давать `ISOLATION-RELAXED`.

## 2. Проверенное evidence

- [x] Linux dual-egress runtime: `antigravity`, `language_server`, bundled `node` → `vpn-direct`; ordinary process → `system-direct`. **[R-002, R-003, R-015]**
- [x] Linux capture profile исправлен по runtime evidence: `auto_route + strict_route`, `auto_redirect=false`. **[R-013, R-015]**
- [x] Process/path rules выполняются до sniff. **[R-002]**
- [x] Agent Tunnel success gated TUN + managed-listener ownership; failed readiness triggers rollback. **[R-001, R-014, R-022]**
- [x] Health не принимает «порт открыт» как ownership evidence. **[R-014, R-022]**
- [x] Linux listener ownership: `/proc/<pid>/fd` socket inode ↔ `/proc/net/tcp{,6}`. **[R-022]**
- [x] Windows native endpoint → `netstat -ano` → PID fixture. **[R-002, R-015]**
- [x] Privileged Agent Tunnel install fail-closed по official SHA-256; installed hash + provenance + tamper detection. **[R-007, R-023]**
- [x] Loopback-only persisted control-plane/proxy invariant. **[R-008]**
- [x] Atomic Settings, Agent Tunnel config, provenance и network journal. **[R-024, R-026]**
- [x] Durable Linux pre-change route/rule/DNS/firewall fingerprint. **[R-001, R-010, R-013, R-016]**
- [x] Reserved Linux route table `20229` + rule priorities `19000..19031`; collision preflight до mutation. **[R-013, R-025]**
- [x] SIGKILL recovery fixture сохраняет unrelated concurrent route/rule state. **[R-010, R-016, R-025]**
- [x] Corrupt journal → validated `previous-good` or fail-closed; broad cleanup запрещён. **[R-026]**
- [x] Authenticated sing-box runtime API exposes source/process/outbound/destination evidence. **[R-002, R-015, R-019]**
- [x] Linux PID → socket inode → sing-box source endpoint → `vpn-direct` → external VPN source proof. **[R-002, R-015]**
- [x] `GET /api/attestation` + Web UI assurance with bounded egress evidence TTL and lifecycle invalidation. **[R-014, R-015, R-019]**
- [x] Domain fallback visibly reported as `ISOLATION-RELAXED`. **[R-003]**
- [x] Linux ordinary-user one-shot privilege bootstrap through fixed-function PolicyKit helper. **[R-006, R-012]**
- [x] Helper revalidates managed path, symlink/owner boundary and SHA-256 around privileged `setcap`. **[R-006, R-007, R-012]**
- [x] Linux capability loss after managed binary replacement is detected and repaired on next explicit Agent Tunnel start. **[R-012]**
- [x] Race detector is part of CI. **[R-014, R-021]**

## 3. P0 — базовый продукт — завершён

- [x] Go monorepo, Windows/Linux builds.
- [x] Embedded responsive PWA + SSE.
- [x] SAFE MODE.
- [x] Agent Tunnel MVP.
- [x] Agent Doctor CLI/API.
- [x] DoH, VPN interface binding, SOCKS5h/HTTP diagnostics.
- [x] Production Cloud Code endpoint pinning.
- [x] Process-only Antigravity launcher.
- [x] Emergency hosts fallback/rollback.
- [x] FMEA register + `riskcheck`.
- [x] CI build/test/release workflows.

## 4. P1 — production hardening

### 4.1 Privilege/lifecycle

- [x] Linux fixed-function one-shot PolicyKit helper; terminal sudo fallback only when attached; UI/control plane/IDE stay ordinary user. **[R-006, R-012]**
- [x] Linux TUN + exact four-capability readiness and automatic repair. **[R-006, R-012]**
- [x] Linux selected VPN exists + UP before mutation. **[R-004]**
- [x] Root/netns runtime path does not mutate file capabilities unnecessarily. **[R-006]**
- [ ] Implement **Windows minimal UAC helper** so whole control plane need not run Administrator. Helper API must be fixed-function/structured, not shell passthrough. **[R-006]**
- [ ] Windows privilege preflight + one-click helper authorization from UI. **[R-006]**
- [x] Graceful Linux SIGTERM before forced kill + `PDEATHSIG=SIGTERM`. **[R-010, R-016]**
- [x] App shutdown waits for managed helper cleanup. **[R-016]**
- [x] Linux elevated-launch guard restores invoking desktop user and never launches IDE as root when identity cannot be proven. **[R-006]**
- [x] Startup transaction: prepare journal → start → readiness → active evidence; failure rollback. **[R-001, R-014, R-022]**
- [ ] Add fault injection at every journal phase: `prepared`, partial mutation, `active`, `recovering`. **[R-001, R-010, R-016, R-026]**
- [ ] Add externally orphaned helper ownership token/fingerprint before any kill/reclaim action. **[R-010, R-022]**
- [ ] Windows exact interface LUID/route-compartment ownership and stale-route cleanup. **[R-027]**
- [ ] Add ordinary-user upgrade fixture: replace managed sing-box, prove lost xattrs are detected/repaired through PolicyKit, then Tunnel starts without whole-app elevation. **[R-012]**

### 4.2 Process isolation and egress assurance

- [x] Live Antigravity process tree with unknown descendants surfaced. **[R-002]**
- [x] Linux exact PID/socket/outbound/external egress proof. **[R-002, R-015]**
- [x] Windows exact live local endpoint → PID attribution. **[R-002, R-015]**
- [ ] Full Windows Agent Tunnel PID/socket → sing-box outbound → controlled external egress proof. **[R-002, R-015]**
- [x] Route conflict preflight for reserved namespace, custom rules, concurrent VPN and Docker/VM-like interfaces. **[R-013, R-025]**
- [ ] Expand real conflict matrix across NetworkManager/systemd-networkd, Docker/Podman/libvirt/VirtualBox/VMware. **[R-013, R-025]**
- [x] Broad domain fallback visibly marks `isolation-relaxed`. **[R-003]**
- [ ] Add negative runtime fixture: unrelated Google client remains `system-direct` in strict mode and intentionally demonstrates relaxed scope only when fallback enabled. **[R-003]**

### 4.3 Health/orchestration contracts

- [x] Evidence health dimensions: managed process, owned listener, TUN, VPN, network journal. **[R-014, R-022, R-026]**
- [x] Composed assurance: process tree + route + PID/socket + external egress. **[R-002, R-014, R-015]**
- [x] Assurance cache TTL/invalidation on data-plane boundaries. **[R-014, R-015]**
- [ ] Explicit transient operation states with timestamps: `installing → starting → stopping → recovering`. **[R-001, R-014]**
- [ ] Operation IDs + cancellation for long web actions. **[R-001, R-014]**
- [x] One typed/validated tunnel options path; Linux `strict_route=true` normalized as invariant. **[R-021]**
- [ ] Exhaustive API/UI → Settings → generated config contract test for every exposed option. **[R-021]**
- [ ] Independent health dimensions `route`, `dns_v4`, `dns_v6`, `egress`, `agent_process`, `backend`. **[R-005, R-011, R-014, R-015]**

### 4.4 Persistence/security/release engineering

- [x] Atomic Settings/Agent Tunnel/provenance/journal persistence. **[R-024]**
- [ ] Migrate remaining SAFE config / Antigravity settings / hosts metadata where semantically appropriate; add interruption injection. **[R-024]**
- [ ] Hosts ownership metadata + creation time/TTL + startup stale warning/auto-removal. **[R-009]**
- [ ] Central diagnostic redaction for bearer/OAuth, cookies, email-like identifiers, user paths and optional IP anonymization. **[R-019]**
- [ ] Windows DACL/security descriptor proof for API secret and sensitive runtime files. **[R-019, R-024]**
- [x] Missing/invalid official SHA-256 blocks privileged install. **[R-023]**
- [ ] General sing-box compatibility contract before version upgrades. **[R-007]**
- [ ] Explicit old network-journal schema migration matrix. **[R-026]**
- [ ] Protect `main` with required CI checks/ruleset. **[R-017]**
- [ ] Windows MSI/MSIX and Linux `.deb`/desktop entry.
- [ ] Code signing. **[R-007]**

## 5. P2 — routing intelligence

- [ ] Route-probe matrix per VPN candidate. **[R-004, R-015]**
- [ ] Stable VPN identity + automatic rebind after interface recreation. **[R-004]**
- [ ] Auto-select fastest healthy egress only after policy/eligibility checks.
- [ ] Per-endpoint policy: OAuth / Cloud Code / model generation / site.
- [ ] Dynamically learn backend hostname from process command line, SNI and logs with review before persistence. **[R-020]**
- [ ] Dynamically learn helper PID/path topology and reconcile with allowlist. **[R-002, R-020]**
- [ ] Replace broad `*.googleapis.com` fallback with reviewed learned process+endpoint policy. **[R-003]**
- [ ] DoH failover with independent health.
- [ ] IPv4/IPv6 independent egress + DNS assurance; add UDP/QUIC. **[R-005]**
- [ ] Backend/account vs transport classifier; authoritative server reject stops transport escalation. **[R-011]**
- [ ] A/B workflow: same account/different egress and same egress/different account. **[R-011]**

## 6. P3 — UX/UI

- [x] Progressive main UI separates SAFE MODE and Agent Tunnel.
- [x] One-action Linux setup card: sing-box / VPN / privileges / runtime readiness.
- [x] Runtime assurance panel: Assurance / Isolation / PID route / External egress / Evidence age.
- [x] Clear PolicyKit explanation; password is handled by OS, not app. **[R-006]**
- [x] `ISOLATION-RELAXED` is visible when domain fallback broadens policy. **[R-003]**
- [ ] Full first-run wizard with recommended mode derived from evidence.
- [ ] Connection topology visualization with expected vs actual egress.
- [ ] Explicit guided ladder `SAFE MODE → AGENT TUNNEL → ELIGIBILITY DIAGNOSIS`.
- [ ] Advanced view: process tree, unknown helpers, per-connection ownership, route/journal details.
- [ ] One-click redacted diagnostic bundle. **[R-019]**
- [ ] PWA degradation notifications.
- [ ] Offline help.
- [ ] RU/EN localization.
- [ ] Risk dashboard generated from `risks/register.json`.

## 7. P4 — verification matrix

- [x] `go test ./...` + `go vet ./...`.
- [x] Race detector CI.
- [x] Linux real TUN lifecycle runtime.
- [x] Linux dual-egress process/path isolation runtime. **[R-002, R-003, R-015]**
- [x] Deterministic external egress observer fixture. **[R-015]**
- [x] Linux PID/socket route-attestation runtime. **[R-002, R-015]**
- [x] Linux crash recovery preserving unrelated route/rule state. **[R-010, R-016, R-025]**
- [x] Corrupt/previous-good journal fixtures. **[R-026]**
- [x] Native Windows endpoint → PID fixture. **[R-002, R-015]**
- [x] Provenance tamper/missing-digest tests. **[R-023]**
- [ ] Full Windows Agent Tunnel egress fixture. **[R-002, R-015]**
- [ ] Windows forced-kill route ownership fixture. **[R-027]**
- [ ] Linux ARM64 privileged runner. **[R-018]**
- [ ] Debian/Fedora-family privileged runtime matrix. **[R-013, R-018]**
- [ ] Docker/Podman/VM conflict fixtures. **[R-013]**
- [ ] Dual-stack A/AAAA + TCP/UDP/QUIC matrix. **[R-005]**
- [ ] Foreign-listener collision test. **[R-022]**
- [ ] Every journal-phase fault injection. **[R-001, R-010, R-016, R-026]**
- [ ] Windows security descriptor fixture. **[R-019, R-024]**
- [ ] Agent Doctor classification corpus. **[R-011]**
- [ ] Diagnostic secret/redaction corpus + fuzzing. **[R-019]**
- [ ] `staticcheck` + `govulncheck`.
- [ ] SBOM + signed provenance/attestations for release artifacts. **[R-007]**

## 8. Definition of done для production Agent Tunnel

Production-ready утверждение допускается только если одновременно:

1. Linux ordinary-user flow не требует ручного `setcap` в normal path; automatic helper подтверждён upgrade fixture. **[R-006, R-012]**
2. Windows control plane не требует whole-app Administrator для normal Tunnel flow. **[R-006]**
3. Linux и Windows имеют полный PID/socket/outbound/external-egress proof. **[R-002, R-015]**
4. Crash/reboot recovery удаляет только owned network state. **[R-001, R-010, R-016, R-025, R-027]**
5. IPv4/IPv6/DNS/UDP/QUIC paths проверяются отдельно. **[R-005]**
6. Domain fallback либо заменён learned policy, либо явно принят как relaxed mode. **[R-003]**
7. Sensitive diagnostics проходят centralized redaction; Windows ACLs доказаны native evidence. **[R-019, R-024]**
8. `main` защищён required status checks. **[R-017]**
9. Release gate по FMEA проходит без неразрешённых release-significant risks.
