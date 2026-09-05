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
| R-001 | P1 durable network transaction + crash-phase rollback proof |
| R-002 | P1 production PID egress attestation; P2 dynamic helper discovery |
| R-003 | P2 replace broad Google domain fallback with learned process/endpoint policy |
| R-004 | P2 VPN interface lifecycle/rebind recovery |
| R-005 | P2/P4 independent IPv4/IPv6 + DNS/UDP/QUIC verification |
| R-006 | P1 minimal privileged helper instead of elevated whole app |
| R-007 | P1 dependency compatibility; P4 provenance/SBOM |
| R-008 | Closed: loopback-only control-plane/proxy invariant |
| R-009 | P1 hosts override ownership + expiry |
| R-010 | P1 stale TUN/route recovery after non-cooperative termination |
| R-011 | P2 backend/account-vs-transport health classification |
| R-012 | P1 capability-preserving Linux sing-box update flow |
| R-013 | P1 route conflict preflight; P4 Docker/VM/distro runtime matrix |
| R-014 | P1 multidimensional health + assurance state machine |
| R-015 | P1 PID/socket/outbound/public-egress attestation; CI dual-egress evidence |
| R-016 | P1 forced-shutdown journal recovery |
| R-017 | P1 protect `main` with required CI checks |
| R-018 | P4 Linux ARM64 + Debian/Fedora runtime coverage |
| R-019 | P1 centralized diagnostic redaction; P4 secret fixtures/fuzz |
| R-020 | P2 dynamic backend endpoint discovery/learning |
| R-021 | P1 settings/UI/orchestrator contract tests |
| R-022 | P1 managed listener/PID ownership verification |
| R-023 | Closed: fail-closed privileged dependency digest policy |
| R-024 | P1 migrate remaining direct persistence writes |
| R-025 | P1 recovery ownership invariants; P4 concurrent route mutation test |
| R-026 | P1 journal corruption recovery; P4 journal fault injection |
| R-027 | P1 Windows route ownership recovery; P4 Windows forced-kill test |

### Проверенное архитектурное evidence

- [x] Linux dual-egress runtime в отдельном `netns`: `antigravity`, `language_server` и bundled `node` выходят через `vpn-direct`, обычный процесс — через `system-direct`.
- [x] Linux capture model исправлен по результатам runtime evidence: `auto_route + strict_route`, `auto_redirect=false`; process/path rules выполняются до sniff.
- [x] Agent Tunnel не возвращает успех до появления TUN и доказанного ownership mixed-listener; неуспешный readiness запускает rollback.
- [x] Health больше не принимает факт «порт открыт» как достаточное доказательство: listener должен принадлежать PID managed sing-box.
- [x] Linux listener ownership доказывается через `/proc/<pid>/fd` socket inode ↔ `/proc/net/tcp{,6}`; Windows — через `netstat -ano` PID.
- [x] Привилегированный Agent Tunnel использует fail-closed verified installer: обязательный release SHA-256, hash установленного binary и persistent provenance; изменение binary после установки детектируется тестом.
- [x] Live Antigravity process-tree inventory строит дерево потомков и явно выводит неизвестные helper-процессы вместо молчаливого предположения, что allowlist полон.
- [x] Persisted control-plane/proxy endpoints fail-closed к loopback-only.
- [x] Settings, Agent Tunnel config, dependency provenance и network-state journal используют atomic temp → fsync/write-through → atomic replace + `previous-good`.
- [x] До любого Linux Agent Tunnel mutation сохраняется durable network baseline: IPv4/IPv6 routes, policy rules, DNS fingerprint и nftables fingerprint.
- [x] Linux Agent Tunnel закреплён за выделенным ownership namespace: route table `20229` и rule-priority range `19000..19031`; collision preflight выполняется до mutation.
- [x] После readiness сохраняется active snapshot и вычисляется conservative ownership delta; reserved namespace дополняет, а не заменяет before/after evidence.
- [x] SIGKILL/crash runtime fixture доказывает восстановление owned TUN/table/rule и сохранение одновременно добавленного чужого route/rule state.
- [x] Повреждённый recovery journal восстанавливается только из валидного `previous-good`; неоднозначное состояние fail-closed и не запускает broad cleanup.
- [x] Stale recovery удаляет только доказуемо принадлежащие предыдущей операции TUN/table/rule ресурсы; DNS/firewall изменения остаются evidence-only и никогда не откатываются автоматически без ownership proof.
- [x] Open/invalid recovery journal является отдельным health evidence и блокирует `healthy` вне активной подтверждённой tunnel-транзакции.
- [x] sing-box 1.14 connection tracker доступен через отдельный authenticated loopback API; runtime evidence содержит source endpoint, process path, destination и выбранный outbound.
- [x] Deterministic external-egress fixture доказывает реальное различие `vpn-direct -> 10.250.0.2` и `system-direct -> 10.251.0.2` глазами одного удалённого observer, а не только по конфигурации.
- [x] Linux PID-level runtime proof соединяет конкретный PID → `/proc` socket inode → sing-box source endpoint → `vpn-direct` → внешний VPN-source address.
- [x] Native Windows CI открывает реальный TCP socket и доказывает exact local endpoint → `netstat -ano` → PID создающего процесса; parser fixtures отдельно покрывают IPv4/IPv6, candidate filtering и ambiguous ownership.
- [x] Composed assurance опубликован read-only через `GET /api/attestation`; Web UI показывает `idle/partial/verified/degraded`, PID-route evidence, external egress и возраст evidence.
- [x] External-egress evidence имеет bounded in-memory cache: success TTL 15 s, failure TTL 3 s, key = managed sing-box PID + VPN interface; API явно возвращает `egress_cached` и `egress_fresh_until`.
- [x] Assurance cache инвалидируется на data-plane reconfigure/start/stop/mode-switch/rollback boundaries и публикует локальное audit-event, поэтому старое внешнее evidence не переживает управляемую смену транспортного состояния.

## P0 — уже реализовано

- [x] Go monorepo structure.
- [x] Windows/Linux source portability.
- [x] Embedded responsive web UI.
- [x] PWA shell.
- [x] SSE event stream.
- [x] sing-box discovery/bootstrap.
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
- [x] Linux capture-first TUN policy: `auto_route + strict_route`; `auto_redirect` intentionally disabled after dual-egress proof exposed bypass semantics.
- [x] bundled Node helper routing constrained by process/path policy.
- [x] LAN/private address exclusion from TUN auto-route.
- [x] Agent Tunnel start/stop/launch HTTP API.
- [x] Agent Tunnel web UI controls and live state.
- [x] emergency hosts override + rollback.
- [x] CI build matrix.
- [x] real Linux TUN lifecycle + dual-egress test in isolated network namespace.
- [x] machine-readable Design-FMEA risk register + `riskcheck` validator.
- [x] tag release workflow with FMEA release gate.

## P1 — Agent Tunnel production hardening

### Privilege and lifecycle

- [ ] **[R-006]** Platform elevation helper: Windows UAC / Linux pkexec/capability-scoped helper only for privileged networking actions; UI/control plane remains ordinary user.
- [ ] Windows privilege preflight before starting TUN; offer one-click elevated helper restart. **[R-006]**
- [x] Linux TUN-device and `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` preflight with actionable `setcap` remediation. **[R-006, R-012]**
- [x] Linux selected VPN-interface existence/UP validation before TUN startup. **[R-004]**
- [x] Verify Linux TUN interface creation, process/path routing, dual-egress isolation and cleanup with a real privileged runtime test in isolated `netns`. **[R-001, R-002, R-003, R-010, R-015]**
- [x] Graceful Linux sing-box shutdown (`SIGTERM`) before forced fallback. **[R-016]**
- [x] Linux parent-death protection (`PDEATHSIG=SIGTERM`). **[R-010, R-016]**
- [x] App shutdown hook waits for managed network helper cleanup. **[R-016]**
- [x] Linux elevated-launch guard: never launch Antigravity as root; recover invoking desktop user when possible. **[R-006]**
- [x] Linux settings/executable discovery uses invoking desktop user rather than `/root` when elevated. **[R-006]**
- [x] Automatic Agent Tunnel startup transaction: managed process → owned listener + TUN + VPN readiness; failure invokes stop/wait rollback. **[R-001, R-014, R-022]**
- [x] Durable pre-change route/rule/DNS/nftables fingerprint, active snapshot, ownership delta and `network-state-last-clean.json` recovery evidence. **[R-001, R-010, R-013, R-016, R-026]**
- [x] Next-start stale recovery for Linux `antigravity-tun`, reserved route table/rule range and derived owned deltas; live previous PID makes recovery fail closed. **[R-010, R-016, R-025]**
- [x] SAFE proxy startup also requires managed-listener ownership and rolls back on readiness timeout. **[R-014, R-022]**
- [ ] Add startup/forced-kill fault injection for every journal phase (`prepared`, partially applied, `active`, `recovering`). **[R-001, R-010, R-016, R-026]**
- [x] Reserve explicit Linux route-table/rule ownership identifiers and preflight collisions so recovery does not rely only on before/after differencing. **[R-013, R-025]**
- [x] Recover a corrupt current journal only from validated `previous-good`; quarantine invalid primary evidence and fail closed when recovery evidence is insufficient. **[R-026]**
- [ ] Complete explicit old-schema migration policy and fixture matrix beyond fail-closed schema rejection. **[R-026]**
- [ ] Windows interface LUID/route-compartment ownership and exact stale-route recovery; broad route deletion remains prohibited until then. **[R-027]**
- [ ] Managed sing-box lifecycle recovery after reboot / externally orphaned process with ownership token before any kill. **[R-010, R-022]**
- [ ] Detect Linux capability loss after managed sing-box replacement and repair through minimal privileged helper. **[R-012]**

### Egress and process isolation

- [x] Live Antigravity process-tree discovery on Linux/Windows with unknown-descendant surfacing. **[R-002]**
- [x] Authenticated sing-box runtime connection evidence records `source/process/outbound/destination/inbound/network`. **[R-002, R-015]**
- [x] External observer attestation proves the `vpn-direct` path has a real externally visible egress consequence and compares it with `system-direct`; observer failure remains incomplete evidence, not a false routing diagnosis. **[R-015, R-019]**
- [x] Linux: correlate a concrete live candidate PID with `/proc` socket ownership, sing-box source endpoint and `vpn-direct`; privileged `netns` CI proves the chain end to end. **[R-002, R-015]**
- [x] Windows: implement exact source-endpoint → `netstat -ano` → candidate PID correlation, cover it by parser fixtures, and prove live socket → PID attribution on a native Windows runner. **[R-002, R-015]**
- [ ] Add full Windows Agent Tunnel runtime proof for PID/socket → sing-box outbound → controlled external egress; only then claim Linux-equivalent end-to-end assurance on Windows. **[R-002, R-015]**
- [x] Verify mixed listener belongs to the managed sing-box PID before trusting health/readiness. **[R-022]**
- [ ] Add ownership token/fingerprint before killing a previously orphaned helper, not only an in-memory `cmd.Process` pointer. **[R-010, R-022]**
- [x] Route conflict preflight for reserved routing namespace, custom policy rules, concurrent VPNs and Docker/Podman/libvirt/VirtualBox/VMware-like interfaces; ambiguous high-risk ownership blocks mutation. **[R-013, R-025]**
- [ ] Expand route-conflict runtime matrix across NetworkManager/systemd-networkd, Docker/Podman and VM stacks. **[R-013, R-025]**
- [ ] Make broad domain fallback visibly `degraded/isolation-relaxed` and prepare migration to process-learned policy. **[R-003]**

### Health/orchestration contracts

- [x] Evidence-based health snapshot with explicit `idle / healthy / degraded`; dimensions include `managed_process`, `mixed_listener_owned`, `tun`, `vpn_interface`, `network_journal`. **[R-014, R-022, R-026]**
- [x] Backend assurance composition implemented for process-tree + sing-box route + PID/socket ownership + external egress with `idle / partial / verified / degraded` semantics. **[R-002, R-014, R-015]**
- [x] Expose/cache composed assurance through read-only `GET /api/attestation` and Web UI; external observer work is bounded by 15 s success / 3 s failure TTL, and callers receive explicit cache/freshness metadata. **[R-014, R-015, R-019]**
- [x] Explicit lifecycle invalidation clears cached external-egress evidence on data-plane reconfigure, managed stop, Agent Tunnel start/stop/restart and startup rollback; invalidation is visible in local event history. **[R-014, R-015]**
- [ ] Extend lifecycle state machine to explicit transient states: `installing → starting → stopping → recovering`, with transition invariants and timestamps. **[R-001, R-014]**
- [ ] Add independent health dimensions: `route`, `dns_v4`, `dns_v6`, `egress`, `agent_process`, `backend`. **[R-005, R-011, R-014, R-015]**
- [ ] Operation IDs and cancellation for long-running web actions. **[R-001, R-014]**
- [x] Persisted tunnel options flow through one validated runtime options object; Linux `strict_route=true` is enforced as an invariant instead of a mutable preference. **[R-021]**
- [ ] Contract tests: every exposed tunnel setting must change runtime config or be explicitly rejected/normalized. **[R-021]**
- [x] Data-plane config mutation is rejected while sing-box is running; stopped updates commit to Manager + atomic persisted Settings transactionally. **[R-021, R-024]**
- [x] Enforce loopback-only control-plane bind and loopback-only local proxy bind in normal mode, including persisted-config validation and tests. **[R-008]**
- [x] Verify mixed listener belongs to managed sing-box and performs an actual TCP connect after ownership proof; a foreign listener cannot satisfy health by port reachability alone. **[R-022]**

### Persistence, diagnostics and dependency safety

- [x] Central atomic-write helper: same-directory temp → file fsync → atomic replace; Unix directory fsync / Windows `MOVEFILE_WRITE_THROUGH`; `previous-good` backup. **[R-024]**
- [x] Settings persistence uses the atomic-write helper. **[R-024]**
- [x] Agent Tunnel generated config uses the atomic-write helper. **[R-024]**
- [x] Verified dependency provenance and network-state journal use the atomic-write helper. **[R-007, R-023, R-024, R-026]**
- [ ] Convert remaining direct writes (SAFE proxy config, Antigravity settings/hosts metadata where appropriate) to atomic transactions and add interruption fault injection. **[R-024]**
- [ ] Structured JSON diagnostic bundle.
- [ ] Central redaction for bearer/OAuth tokens, cookies, email-like identifiers and user paths; optional IP anonymization before any egress evidence can enter a support bundle. **[R-019]**
- [ ] Verify/harden Windows DACL/security descriptor for `sing-box-api-secret` and other sensitive runtime files using native Windows security evidence; POSIX `FileMode` bits must never be treated as Windows ACL proof. **[R-019, R-024]**
- [ ] Emergency hosts override ownership metadata, creation time/TTL, startup stale warning and safe auto-removal. **[R-009]**
- [x] Generated Agent Tunnel config validated against pinned real sing-box in CI. **[R-007]**
- [ ] General sing-box schema/behavior compatibility contract for future upgrades. **[R-007]**
- [x] Privileged Agent Tunnel install is fail-closed on missing/invalid official SHA-256; verified archive → installed binary hash → persisted provenance; binary tampering invalidates reuse. **[R-007, R-023]**
- [ ] Protect `main` and require CI test, Linux TUN runtime, Windows native unit/runtime evidence, FMEA/riskcheck and platform build checks at repository ruleset level. **[R-017]**
- [ ] Windows installer/MSIX or MSI.
- [ ] Linux `.deb` and desktop entry.
- [ ] Code signing pipeline. **[R-007]**

## P2 — routing intelligence

- [ ] Route probe matrix for each candidate VPN interface. **[R-004, R-015]**
- [ ] Auto-select fastest healthy egress only after policy/eligibility checks.
- [ ] Per-endpoint policy: OAuth / Cloud Code / model generation / Antigravity site.
- [ ] Dynamically learn Antigravity backend hostnames from language-server command line, SNI and logs instead of relying only on a static set. **[R-020]**
- [ ] Dynamically learn helper PID/path topology and reconcile with allowlisted policy; current process-tree + PID/socket attestation supply the discovery/verification substrate. **[R-002, R-003, R-020]**
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
- [ ] One-click diagnostic bundle combining sing-box logs + Agent Doctor + route/TUN/journal state.
- [x] Surface composed runtime assurance summary in main Web UI: state, PID-route ratio, external egress, cache/freshness age and full evidence JSON on demand.
- [ ] Expand Advanced UI with raw `/api/process-tree`, unknown helpers, per-connection PID ownership, all health dimensions and open recovery journal.
- [ ] PWA notifications for proxy/tunnel degradation.
- [ ] Offline help pages.
- [ ] RU/EN localization.
- [ ] Advanced view hidden behind toggle.
- [ ] Clear warning before privileged TUN startup and visible `system proxy untouched / isolation relaxed` status. **[R-003, R-006]**
- [ ] Risk dashboard generated from `risks/register.json`: highest RPN, mitigation status, last review and release blockers.

## P4 — quality and assurance

- [ ] Integration tests with mock HTTP CONNECT/SOCKS server.
- [ ] TUN config golden tests for Windows/Linux.
- [x] Native Windows runner unit/runtime job executes Windows-specific proxy/antigravity/app tests and `go vet`; live socket fixture proves exact local endpoint → `netstat -ano` → current PID. **[R-002, R-015]**
- [x] Linux network namespace runtime fixture for real TUN startup/health/cleanup.
- [x] Linux PID/path-aware dual-egress runtime test: Antigravity/language_server/bundled helper → `vpn-direct`, ordinary client → `system-direct`. **[R-002, R-003, R-015]**
- [x] Deterministic external-egress runtime test: the same remote observer sees `vpn-direct` and `system-direct` from distinct expected source addresses. **[R-015]**
- [x] Linux live PID/socket route-attestation runtime test: candidate PID → socket inode/source endpoint → sing-box connection → `vpn-direct` → expected external VPN source. **[R-002, R-015]**
- [ ] Negative test: unrelated Google client must retain `system-direct` when domain fallback is enabled/disabled according to isolation mode. **[R-003]**
- [ ] Linux ARM64 privileged TUN runtime runner; current ARM64 coverage is build-only. **[R-018]**
- [ ] Distro runtime matrix: Ubuntu/Debian/Fedora family; systemd-resolved, nftables, NetworkManager. **[R-013, R-018]**
- [ ] Docker/Podman and VM route-conflict integration fixtures. **[R-013]**
- [ ] Dual-stack A/AAAA + TCP/UDP/QUIC egress tests. **[R-005]**
- [ ] Port-collision test with foreign listener on 7890; readiness must prove foreign PID cannot become healthy. **[R-022]**
- [ ] Fault-injection tests across each TUN startup phase and forced-shutdown recovery. **[R-001, R-010, R-016]**
- [x] Concurrent-network-manager negative recovery test: add unrelated route table/rule while tunnel is active, crash, recover, prove unrelated state survives. **[R-025]**
- [x] Recovery-journal corruption/`previous-good` fixtures prove corrupted primary evidence cannot trigger broad cleanup; explicit old-schema migration matrix remains P1. **[R-026]**
- [ ] Windows forced-kill recovery fixture proving exact interface-LUID/route cleanup and preservation of unrelated routes. **[R-027]**
- [ ] Full Windows Agent Tunnel live PID/socket/outbound/external-egress fixture matching the Linux assurance chain. **[R-002, R-015]**
- [ ] Windows security-descriptor fixture proving sensitive runtime files are not accessible to unintended principals. **[R-019, R-024]**
- [ ] Agent Doctor fixture matrix for geo/account, auth, quota, MCP/hooks and backend 5xx. **[R-011]**
- [ ] Diagnostic secret/redaction fixture corpus + fuzz tests. **[R-019]**
- [ ] Atomic-write interruption/fault-injection tests beyond normal old/new completeness tests. **[R-024]**
- [x] Provenance tamper and missing-digest evidence tests. **[R-023]**
- [ ] race detector in CI.
- [ ] staticcheck/govulncheck.
- [x] `go run ./cmd/riskcheck` in normal CI; `-release` is enforced by tag release workflow.
- [ ] SBOM generation on release. **[R-007]**
- [ ] provenance/attestations for release binaries. **[R-007]**
