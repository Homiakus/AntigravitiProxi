# Карта миграции PowerShell v5 → Go

| Возможность v5 | Go | Примечание |
|---|---:|---|
| Проверка VPN интерфейса | ✅ | `net.Interfaces`, эвристика VPN |
| Поиск sing-box | ✅ | managed path + PATH |
| Portable bootstrap | ✅ | GitHub Releases |
| SHA-256 verification | ✅ | digest из Release API |
| Cloudflare DoH | ✅ | pinned transport |
| Google DoH fallback | ✅ | pinned transport |
| Mixed HTTP/SOCKS proxy | ✅ | sing-box mixed inbound |
| `bind_interface` | ✅ | Windows/Linux |
| HTTP proxy tests | ✅ | native `net/http` |
| SOCKS5h remote DNS test | ✅ | собственный SOCKS5 dialer |
| TLS verification | ✅ | не отключается |
| DNS integrity comparison | ✅ | System + 2 pinned DoH |
| Force production Cloud Code endpoint | ✅ | Windows/Linux settings paths |
| Process-only proxy launch | ✅ | основной режим |
| SAFE MODE | ✅ | основной UX path |
| Emergency hosts override | ✅ | Windows/Linux, Admin/root |
| Marker-scoped hosts rollback | ✅ | встроено |
| Diagnostic log | ✅ | web diagnostics + sing-box logs |
| TUI/PowerShell menu | заменено | responsive web/PWA |
| WinINET global proxy | намеренно не перенесено | ломало изоляцию приложений |
| WinHTTP global proxy | намеренно не перенесено | не требуется SAFE MODE |
| User-wide proxy ENV | намеренно не перенесено | proxy только дочернему Antigravity |
| Restart-as-admin | ⏳ | planned platform elevation helper |
| Background service/autostart | ⏳ | planned |
| Signed releases | ⏳ | planned |
