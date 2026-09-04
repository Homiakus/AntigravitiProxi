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
- [x] Linux TUN-device and `CAP_NET_ADMIN`/`CAP_NET_RAW` preflight with actionable `setcap` remediation.
- [x] Linux selected VPN-interface existence/UP validation before TUN startup.
- [x] Verify Linux TUN interface creation and cleanup with a real privileged runtime test in isolated `netns`.
- [ ] Verify that Antigravity, language server and bundled helpers actually egress through selected VPN by PID/source path.
- [x] Graceful Linux sing-box shutdown (`SIGTERM`) before forced fallback.
- [x] Linux parent-death protection (`PDEATHSIG=SIGTERM`) to avoid orphan TUN/routes/nftables state.
- [x] App shutdown hook waits for managed network helper cleanup.
- [x] Linux elevated-launch guard: do not launch Antigravity as root; recover invoking desktop user when possible.
- [x] Linux settings/executable discovery uses invoking desktop user rather than `/root` when elevated.
- [ ] Automatic rollback watchdog if Agent Tunnel startup is partial or sing-box crashes.
- [ ] Persist previous route/DNS state fingerprint for diagnostics and recovery verification.
- [ ] Detect and recover stale `antigravity-tun` interface after unclean shutdown that survives external failure modes.
- [ ] Managed sing-box lifecycle recovery after reboot / externally orphaned process.
- [ ] PID ownership verification before killing stale processes.
- [ ] Health state machine: `idle → installing → starting → healthy/degraded → stopping`.
- [ ] Separate health dimensions: `mixed_proxy`, `tun`, `dns`, `route`, `agent_process`, `backend`.
- [ ] Operation IDs and cancellation for long-running web actions.
- [ ] Atomic config writes + fsync + backup.
- [ ] Structured JSON diagnostics export/download.
- [ ] Redaction layer for IP/user paths before sharing diagnostics.
- [ ] Automatic endpoint discovery from Antigravity language_server command line and logs.
- [x] Generated Agent Tunnel config validated against pinned real sing-box in CI.
- [ ] General schema compatibility layer for future sing-box versions.
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
- [x] Linux network namespace runtime test fixture for real TUN + nftables/auto_redirect startup/health/cleanup.
- [ ] Linux ARM64 privileged TUN runtime runner; current ARM64 coverage is build-only.
- [ ] Distro runtime matrix (Ubuntu/Debian/Fedora family) for TUN/systemd-resolved/nftables interactions.
- [ ] Test that unrelated process traffic resolves/routes through `local-dns/system-direct` at runtime.
- [ ] Test that Antigravity process names and path regexes select `vpn-direct` at runtime.
- [ ] Fuzz tests for archive extraction, settings editing and log redaction.
- [ ] race detector in CI.
- [ ] staticcheck/govulncheck.
- [ ] SBOM generation on release.
- [ ] provenance/attestations for release binaries.
