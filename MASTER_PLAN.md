# MASTER PLAN — AntigravitiProxi

## Управление архитектурными рисками

Риски являются частью планирования, а не отдельным отчётом. Источник истины — [`risks/register.json`](risks/register.json), методика и архитектурный разбор — [`docs/ARCHITECTURE_FMEA.md`](docs/ARCHITECTURE_FMEA.md).

Правила:

- каждый незакрытый риск обязан иметь `owner`, S/O/D, RPN, mitigation, verification и `target_milestone`;
- каждый незакрытый риск обязан присутствовать в этом плане; это проверяет `go run ./cmd/riskcheck`;
- `RPN >= 150` или `Severity >= 9` считается release-significant;
- release-tag должен проходить `go run ./cmd/riskcheck -release`; high/critical риск должен быть `closed` либо явно `accepted` с документированной причиной;
- FMEA пересматривается после изменения TUN/routing/privilege модели, после сетевого инцидента и перед каждым релизом;
- снижение RPN допустимо только после появления проверяемого control/evidence, а не после изменения формулировки риска.

### Risk-to-plan index

| Risk | Главный этап/действие |
|---|---|
| R-001 | P1 transactional startup + rollback watchdog + state fingerprint |
| R-002 | P1 production PID egress attestation; P2 dynamic helper discovery |
| R-003 | P2 replace broad Google domain fallback with learned process/endpoint policy |
| R-004 | P2 VPN interface lifecycle/rebind recovery |
| R-005 | P2/P4 independent IPv4/IPv6 + DNS/UDP/QUIC verification |
| R-006 | P1 minimal privileged helper instead of elevated whole app |
| R-007 | P1 dependency compatibility; P4 provenance/SBOM |
| R-008 | P1 enforce loopback-only control plane |
| R-009 | P1 hosts override ownership + expiry |
| R-010 | P1 stale TUN/route recovery after non-cooperative termination |
| R-011 | P2 backend/account-vs-transport health classification |
| R-012 | P1 capability-preserving Linux sing-box update flow |
| R-013 | P1 route conflict preflight; P4 Docker/VM/distro runtime matrix |
| R-014 | P1 multidimensional health state machine |
| R-015 | P1 production selected-egress attestation; CI dual-egress evidence |
| R-016 | P1 state fingerprint + forced-shutdown recovery |
| R-017 | P1 protect `main` with required CI checks |
| R-018 | P4 Linux ARM64 + Debian/Fedora runtime coverage |
| R-019 | P1 centralized diagnostic redaction; P4 secret fixtures/fuzz |
| R-020 | P2 dynamic backend endpoint discovery/learning |
| R-021 | P1 settings/UI/orchestrator contract tests |
| R-022 | P1 managed listener/PID ownership verification |
| R-023 | P1 fail-closed dependency digest policy |
| R-024 | P1 atomic/fsync configuration persistence |

## P0 — уже реализовано

- [x] Go monorepo structure.
- [x] Windows/Linux source portability.
- [x] Embedded responsive web UI.
- [x] PWA shell.
- [x] SSE event stream.
- [x] sing-box discovery/bootstrap.
- [x] GitHub Release digest verification when digest metadata is present. See R-023 for fail-closed hardening.
- [x] DoH routing.
- [x] VPN interface selection/binding.
- [x] HTTP proxy diagnostics.
- [x] SOCKS5h diagnostics.
- [x] production Cloud Code endpoint override.
- [x] inherited `CLOUD_CODE_URL` sanitization + production pin.
- [x] process-only Antigravity launcher.
- [x] SAFE MODE.
- [x] Agent Doctor CLI + web API.
- [x] **AGENT TUNNEL MVP**: sing-box TUN + process-aware routing.
- [x] Agent Tunnel Windows/Linux support gate and privilege hints.
- [x] Agent Tunnel secure DoH for Google/Antigravity namespaces.
- [x] Agent Tunnel `system-direct` fallback for unrelated applications.
- [x] Agent Tunnel Linux `auto_redirect`.
- [x] bundled Node helper routing constrained by process/path policy.
- [x] LAN/private address exclusion from TUN auto-route.
- [x] Agent Tunnel start/stop/launch HTTP API.
- [x] Agent Tunnel web UI controls and live state.
- [x] emergency hosts override + rollback.
- [x] CI build matrix.
- [x] real Linux TUN lifecycle test in isolated network namespace.
- [x] machine-readable Design-FMEA risk register + `riskcheck` validator.
- [x] tag release workflow (risk gate is added in P1 governance hardening).

## P1 — Agent Tunnel production hardening

### Privilege and lifecycle

- [ ] **[R-006]** Platform elevation helper: Windows UAC / Linux pkexec/capability-scoped helper only for privileged networking actions; UI/control plane remains ordinary user.
- [ ] Windows privilege preflight before starting TUN; offer one-click elevated helper restart. **[R-006]**
- [x] Linux TUN-device and `CAP_NET_ADMIN`/`CAP_NET_RAW` preflight with actionable `setcap` remediation. **[R-006, R-012]**
- [x] Linux selected VPN-interface existence/UP validation before TUN startup. **[R-004]**
- [x] Verify Linux TUN interface creation and cleanup with a real privileged runtime test in isolated `netns`. **[R-001, R-010]**
- [x] Graceful Linux sing-box shutdown (`SIGTERM`) before forced fallback. **[R-016]**
- [x] Linux parent-death protection (`PDEATHSIG=SIGTERM`). **[R-010, R-016]**
- [x] App shutdown hook waits for managed network helper cleanup. **[R-016]**
- [x] Linux elevated-launch guard: never launch Antigravity as root; recover invoking desktop user when possible. **[R-006]**
- [x] Linux settings/executable discovery uses invoking desktop user rather than `/root` when elevated. **[R-006]**
- [ ] Automatic startup transaction + rollback watchdog if Agent Tunnel partially applies and then fails. **[R-001]**
- [ ] Persist pre-change route/rule/DNS/nftables state fingerprint and post-stop recovery evidence. **[R-001, R-013, R-016]**
- [ ] Detect/recover stale `antigravity-tun` and owned policy state after SIGKILL/reboot/external failure. **[R-010, R-016]**
- [ ] Managed sing-box lifecycle recovery after reboot / externally orphaned process. **[R-010]**
- [ ] Detect Linux capability loss after managed sing-box replacement and repair through minimal privileged helper. **[R-012]**

### Egress and process isolation

- [ ] Verify on the production host that discovered Antigravity PID tree actually uses selected interface/public egress; mismatch must block `healthy`. **[R-002, R-015]**
- [ ] PID/process ownership verification before trusting/killing a managed listener/helper. **[R-022]**
- [ ] Route conflict preflight for Docker/Podman, libvirt/VM, NetworkManager/systemd-networkd, concurrent VPNs and custom policy-routing tables. **[R-013]**
- [ ] Make broad domain fallback visibly `degraded/isolation-relaxed` and prepare migration to process-learned policy. **[R-003]**

### Health/orchestration contracts

- [ ] Health state machine: `idle → installing → starting → healthy/degraded → stopping → recovering`. **[R-001, R-014]**
- [ ] Separate health dimensions: `mixed_proxy`, `tun`, `route`, `dns_v4`, `dns_v6`, `egress`, `agent_process`, `backend`. **[R-005, R-011, R-014, R-015]**
- [ ] Operation IDs and cancellation for long-running web actions. **[R-001, R-014]**
- [ ] Single validated tunnel-options object used by persisted Settings, API, UI and `StartAgentTunnel`. **[R-021]**
- [ ] Contract tests: every exposed tunnel setting must change runtime config or be rejected. **[R-021]**
- [ ] Enforce loopback-only control-plane bind and loopback-only local proxy bind in normal mode. **[R-008]**
- [ ] Verify mixed listener belongs to managed sing-box and performs expected protocol handshake; a foreign listener on the port must fail health. **[R-022]**

### Persistence, diagnostics and dependency safety

- [ ] Atomic config writes: temp file → fsync → rename → previous-good backup. **[R-024]**
- [ ] Structured JSON diagnostic bundle.
- [ ] Central redaction for bearer/OAuth tokens, cookies, email-like identifiers and user paths; optional IP anonymization. **[R-019]**
- [ ] Emergency hosts override ownership metadata, creation time/TTL, startup stale warning and safe auto-removal. **[R-009]**
- [x] Generated Agent Tunnel config validated against pinned real sing-box in CI. **[R-007]**
- [ ] General sing-box schema/behavior compatibility contract for future upgrades. **[R-007]**
- [ ] Fail closed if official release digest is absent; never install a privileged binary on warning-only verification. **[R-023]**
- [ ] Protect `main` and require CI test, Linux TUN runtime, FMEA/riskcheck and platform build checks. **[R-017]**
- [ ] Windows installer/MSIX or MSI.
- [ ] Linux `.deb` and desktop entry.
- [ ] Code signing pipeline. **[R-007]**

## P2 — routing intelligence

- [ ] Route probe matrix for each candidate VPN interface. **[R-004, R-015]**
- [ ] Auto-select fastest healthy egress only after policy/eligibility checks.
- [ ] Per-endpoint policy: OAuth / Cloud Code / model generation / Antigravity site.
- [ ] Dynamically learn Antigravity backend hostnames from language-server command line, SNI and logs instead of relying only on a static set. **[R-020]**
- [ ] Dynamically learn helper PID/path topology and reconcile with allowlisted policy. **[R-002, R-003, R-020]**
- [ ] Replace broad `*.googleapis.com` fallback with narrow learned process+endpoint routing wherever process attribution is available. **[R-003]**
- [ ] Failover Cloudflare DoH ↔ Google DoH with independent health.
- [ ] DNS poisoning confidence score instead of boolean mismatch.
- [ ] IPv4/IPv6 independent health and selected-egress attestation; explicitly cover UDP/QUIC. **[R-005]**
- [ ] Optional multiple upstream proxies/VPN interfaces.
- [ ] Transparent reconnect after VPN interface recreation. **[R-004]**
- [ ] A/B diagnostic workflow: same account/different egress and same egress/different account.
- [ ] Automatic distinction between transport failure and explicit server-side geo/account eligibility rejection; stop network escalation when server rejection is authoritative. **[R-011]**

## P3 — UX

- [ ] First-run wizard including privilege/capability status and risk-aware recommended mode.
- [ ] Connection topology visualization with actual/expected egress.
- [ ] Explicit transport ladder: `SAFE MODE → AGENT TUNNEL → ELIGIBILITY DIAGNOSIS`.
- [ ] One-click diagnostic bundle combining sing-box logs + Agent Doctor + route/TUN state.
- [ ] PWA notifications for proxy/tunnel degradation.
- [ ] Offline help pages.
- [ ] RU/EN localization.
- [ ] Advanced view hidden behind toggle.
- [ ] Clear warning before privileged TUN startup and visible `system proxy untouched / isolation relaxed` status. **[R-003, R-006]**
- [ ] Risk dashboard generated from `risks/register.json`: highest RPN, mitigation status, last review and release blockers.

## P4 — quality and assurance

- [ ] Integration tests with mock HTTP CONNECT/SOCKS server.
- [ ] TUN config golden tests for Windows/Linux.
- [ ] Windows runner integration test for route/process matching where runner permissions allow it. **[R-002, R-015]**
- [x] Linux network namespace runtime fixture for real TUN + nftables/auto_redirect startup/health/cleanup.
- [ ] Linux PID/path-aware dual-egress runtime test: Antigravity/language_server/bundled helper → `vpn-direct`, ordinary client → `system-direct`. **[R-002, R-003, R-015]**
- [ ] Negative test: unrelated Google client must retain `system-direct` when strict process isolation is selected. **[R-003]**
- [ ] Linux ARM64 privileged TUN runtime runner; current ARM64 coverage is build-only. **[R-018]**
- [ ] Distro runtime matrix: Ubuntu/Debian/Fedora family; systemd-resolved, nftables, NetworkManager. **[R-013, R-018]**
- [ ] Docker/Podman and VM route-conflict integration fixtures. **[R-013]**
- [ ] Dual-stack A/AAAA + TCP/UDP/QUIC egress tests. **[R-005]**
- [ ] Port-collision test with foreign listener on 7890. **[R-022]**
- [ ] Fault-injection tests across each TUN startup phase and forced-shutdown recovery. **[R-001, R-010, R-016]**
- [ ] Agent Doctor fixture matrix for geo/account, auth, quota, MCP/hooks and backend 5xx. **[R-011]**
- [ ] Diagnostic secret/redaction fixture corpus + fuzz tests. **[R-019]**
- [ ] Atomic-write interruption tests. **[R-024]**
- [ ] Installer missing-digest negative test. **[R-023]**
- [ ] race detector in CI.
- [ ] staticcheck/govulncheck.
- [ ] `go run ./cmd/riskcheck` in normal CI; `-release` as release gate.
- [ ] SBOM generation on release. **[R-007]**
- [ ] provenance/attestations for release binaries. **[R-007]**
