# Карта миграции PowerShell v5 → Go

| Возможность v5 / новая capability | Go | Примечание |
|---|---:|---|
| Проверка VPN интерфейса | ✅ | `net.Interfaces`, VPN heuristics + explicit selection |
| Поиск sing-box | ✅ | managed path + PATH |
| Portable bootstrap | ✅ | GitHub Releases, pinned `sing-box 1.14.0` |
| SHA-256 verification | ✅ | privileged Agent Tunnel install fail-closed on missing/invalid official digest |
| Installed binary provenance/tamper detection | ✅ | hash + persisted provenance |
| Cloudflare DoH | ✅ | pinned transport |
| Google DoH fallback | ✅ | pinned transport |
| Mixed HTTP/SOCKS proxy | ✅ | sing-box mixed inbound |
| `bind_interface` | ✅ | Windows/Linux |
| HTTP proxy tests | ✅ | native `net/http` |
| SOCKS5h remote DNS test | ✅ | собственный SOCKS5 dialer |
| TLS verification | ✅ | не отключается |
| DNS integrity comparison | ✅ | System + 2 pinned DoH |
| Force production Cloud Code endpoint | ✅ | Windows/Linux settings paths |
| Process-only proxy launch | ✅ | SAFE MODE основной path |
| SAFE MODE | ✅ | не меняет global system proxy |
| Agent Tunnel | ✅ | TUN + process/path policy + `vpn-direct`/`system-direct` |
| Linux strict capture profile | ✅ | `auto_route=true`, `strict_route=true`, `auto_redirect=false` по runtime evidence |
| Linux one-click privilege preparation | ✅ | ordinary-user app → one fixed-function PolicyKit helper; exact capabilities only |
| Linux capability-loss repair after binary replacement | ✅ | автоматически на следующем explicit Agent Tunnel start; upgrade/distro fixture ещё P1 |
| Runtime route assurance | ✅ | process tree → PID/socket → sing-box outbound → external egress |
| Explicit isolation-relaxed state | ✅ | domain fallback не маскируется под strict isolation |
| Durable Linux network-state recovery | ✅ | journal + reserved ownership namespace + conservative cleanup |
| Emergency hosts override | ✅ | Windows/Linux, privileged fallback |
| Marker-scoped hosts rollback | ✅ | встроено; TTL/ownership metadata ещё P1 |
| Diagnostic log | ✅ | web diagnostics + sing-box logs + Agent Doctor |
| TUI/PowerShell menu | заменено | responsive embedded PWA |
| WinINET global proxy | намеренно не перенесено | нарушал изоляцию приложений |
| WinHTTP global proxy | намеренно не перенесено | не требуется SAFE MODE |
| User-wide proxy ENV | намеренно не перенесено | proxy только дочернему Antigravity |
| Windows minimal UAC helper | ⏳ | P1/R-006; current Windows Agent Tunnel may still require Administrator |
| Background service/autostart | ⏳ | не является prerequisite для текущего control plane |
| Signed releases / SBOM / provenance | ⏳ | P4/R-007 |
