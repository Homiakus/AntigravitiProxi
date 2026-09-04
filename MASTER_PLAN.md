# MASTER PLAN — AntigravitiProxi

## P0 — уже реализовано

- [x] Go monorepo structure.
- [x] Windows/Linux source portability.
- [x] Embedded responsive web UI.
- [x] PWA shell.
- [x] SSE event stream.
- [x] sing-box discovery/bootstrap.
- [x] GitHub Release digest verification.
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
- [x] bundled Node helper routing constrained by process + Google destination.
- [x] LAN/private address exclusion from TUN auto-route.
- [x] Agent Tunnel start/stop/launch HTTP API.
- [x] Agent Tunnel web UI controls and live state.
- [x] emergency hosts override + rollback.
- [x] CI build matrix.
- [x] tag release workflow.

## P1 — Agent Tunnel production hardening

- [ ] Platform elevation helper: Windows UAC / Linux pkexec/sudo only for privileged actions.
- [ ] Windows privilege preflight before starting TUN; offer one-click elevated restart.
- [ ] Linux capability preflight for `CAP_NET_ADMIN`/`CAP_NET_RAW` and nftables/nfqueue readiness.
- [ ] Verify TUN interface creation and route ownership after startup, not only local mixed-port health.
- [ ] Verify that `Antigravity.exe`, language server and bundled helpers actually egress through selected VPN.
- [ ] Automatic rollback watchdog if Agent Tunnel startup is partial or sing-box crashes.
- [ ] Persist previous route/DNS state fingerprint for diagnostics and recovery verification.
- [ ] Detect and recover stale `antigravity-tun` interface after unclean shutdown.
- [ ] Managed sing-box lifecycle recovery after parent crash.
- [ ] PID ownership verification before killing stale processes.
- [ ] Health state machine: `idle → installing → starting → healthy/degraded → stopping`.
- [ ] Separate health dimensions: `mixed_proxy`, `tun`, `dns`, `route`, `agent_process`, `backend`.
- [ ] Operation IDs and cancellation for long-running web actions.
- [ ] Atomic config writes + fsync + backup.
- [ ] Structured JSON diagnostics export/download.
- [ ] Redaction layer for IP/user paths before sharing diagnostics.
- [ ] Automatic endpoint discovery from Antigravity language_server command line and logs.
- [ ] Detect unsupported/changed sing-box schema and version compatibility.
- [ ] Windows installer/MSIX or MSI.
- [ ] Linux `.deb` and system desktop entry.
- [ ] Code signing pipeline.

## P2 — routing intelligence

- [ ] Route probe matrix for each candidate VPN interface.
- [ ] Auto-select fastest healthy egress.
- [ ] Per-endpoint policy: OAuth / Cloud Code / model-generation / Antigravity site.
- [ ] Dynamically learn Antigravity backend hostnames from SNI/logs instead of relying only on a static domain set.
- [ ] Failover Cloudflare DoH ↔ Google DoH.
- [ ] DNS poisoning confidence score instead of boolean mismatch.
- [ ] IPv4/IPv6 independent health state.
- [ ] Optional multiple upstream proxies/VPN interfaces.
- [ ] Transparent reconnect after VPN interface recreation.
- [ ] Agent-process egress verification by PID/process-path and remote endpoint.
- [ ] A/B diagnostic workflow: same account/different egress and same egress/different account.
- [ ] Automatic distinction between transport failure and server-side geo/account eligibility rejection.

## P3 — UX

- [ ] First-run wizard.
- [ ] Connection topology visualization.
- [ ] Explicit transport ladder: `SAFE MODE → AGENT TUNNEL → ELIGIBILITY DIAGNOSIS`.
- [ ] One-click diagnostic bundle combining sing-box logs + Agent Doctor + route/TUN state.
- [ ] PWA notifications for proxy/tunnel degradation.
- [ ] Offline help pages.
- [ ] RU/EN localization.
- [ ] Advanced view hidden behind toggle.
- [ ] Clear warning before privileged TUN startup and a visible `system proxy untouched` indicator.

## P4 — quality

- [ ] Integration tests with mock HTTP CONNECT/SOCKS server.
- [ ] TUN config golden tests for Windows/Linux.
- [ ] Windows runner integration test for route/process matching where runner permissions allow it.
- [ ] Linux network namespace test fixture for TUN + nftables/auto_redirect.
- [ ] Test that unrelated process traffic resolves/routs through `system-local/system-direct`.
- [ ] Test that Antigravity process names and path regexes select `agent-vpn`.
- [ ] Fuzz tests for archive extraction, settings editing and log redaction.
- [ ] race detector in CI.
- [ ] staticcheck/govulncheck.
- [ ] SBOM generation on release.
- [ ] provenance/attestations for release binaries.
