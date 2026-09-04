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
- [x] process-only Antigravity launcher.
- [x] SAFE MODE.
- [x] emergency hosts override + rollback.
- [x] CI build matrix.
- [x] tag release workflow.

## P1 — production hardening

- [ ] Platform elevation helper: Windows UAC / Linux pkexec/sudo only for privileged actions.
- [ ] Managed sing-box lifecycle recovery after parent crash.
- [ ] PID ownership verification before killing stale processes.
- [ ] Health state machine: `idle → installing → starting → healthy/degraded → stopping`.
- [ ] Operation IDs and cancellation for long-running web actions.
- [ ] Atomic config writes + fsync + backup.
- [ ] Structured JSON diagnostics export/download.
- [ ] Redaction layer for IP/user paths before sharing diagnostics.
- [ ] Automatic endpoint discovery from Antigravity language_server command line.
- [ ] Detect unsupported/changed sing-box schema and version compatibility.
- [ ] Windows installer/MSIX or MSI.
- [ ] Linux `.deb` and system desktop entry.
- [ ] Code signing pipeline.

## P2 — routing intelligence

- [ ] Route probe matrix for each candidate VPN interface.
- [ ] Auto-select fastest healthy egress.
- [ ] Per-endpoint policy: OAuth / Cloud Code / Antigravity site.
- [ ] Failover Cloudflare DoH ↔ Google DoH.
- [ ] DNS poisoning confidence score instead of boolean mismatch.
- [ ] IPv4/IPv6 independent health state.
- [ ] Optional multiple upstream proxies/VPN interfaces.
- [ ] Transparent reconnect after VPN interface recreation.

## P3 — UX

- [ ] First-run wizard.
- [ ] Connection topology visualization.
- [ ] One-click diagnostic bundle.
- [ ] PWA notifications for proxy degradation.
- [ ] Offline help pages.
- [ ] RU/EN localization.
- [ ] Advanced view hidden behind toggle.

## P4 — quality

- [ ] Integration tests with mock HTTP CONNECT/SOCKS server.
- [ ] Fuzz tests for archive extraction and settings editing.
- [ ] Windows runner integration test.
- [ ] Linux network namespace test fixture.
- [ ] race detector in CI.
- [ ] staticcheck/govulncheck.
- [ ] SBOM generation on release.
- [ ] provenance/attestations for release binaries.
