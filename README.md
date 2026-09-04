# AntigravitiProxi

Кроссплатформенная Go-реализация `Antigravity-Proxy-Manager-v5.ps1` для Windows и Linux.

Проект теперь использует **двухуровневую транспортную схему**:

1. **SAFE MODE** — лёгкий process-only HTTP/SOCKS proxy без изменения системных маршрутов.
2. **AGENT TUNNEL** — привилегированный sing-box TUN с process-aware routing для случая, когда OAuth/регистрация работают, но внутренний агент Antigravity игнорирует `HTTP_PROXY` и завершается ошибкой `Agent execution terminated due to error`.

Основной принцип остаётся прежним: не включать глобальный WinINET/WinHTTP proxy и не ломать Fusion 360, Autodesk Access и другие программы.

## Что реализовано

- один статический Go-бинарник без runtime-зависимостей приложения;
- Windows и Linux;
- лёгкий web UI на стандартном `net/http`, без React/Node/npm;
- UI встроен в бинарник через `embed`;
- PWA: manifest + service worker, адаптивный интерфейс;
- локальный control plane только на `127.0.0.1:48765` по умолчанию;
- local mixed proxy `HTTP CONNECT + SOCKS5` на `127.0.0.1:7890` через `sing-box`;
- автономная установка официального `sing-box` из GitHub Releases с проверкой `SHA-256 digest`;
- Cloudflare DoH и Google DoH;
- `bind_interface` к выбранному VPN-интерфейсу;
- автоматическое обнаружение вероятных VPN-интерфейсов (`Amnezia`, `WireGuard`, `wg`, `tun`, `Tailscale`, `Outline`);
- диагностика System DNS ↔ pinned Cloudflare DoH ↔ pinned Google DoH;
- HTTP proxy tests и собственный SOCKS5h remote-DNS test;
- принудительный production Cloud Code endpoint;
- очистка унаследованного `CLOUD_CODE_URL` перед запуском IDE;
- process-only запуск Antigravity IDE;
- **Agent Tunnel: sing-box TUN + process_name/process_path_regex routing**;
- secure DoH только для Google/Antigravity namespaces, локальный resolver для остального DNS;
- отдельный `system-direct` outbound для приложений, не относящихся к Antigravity;
- Linux `auto_redirect` в Agent Tunnel;
- Windows/Linux privilege hints для TUN;
- встроенный **Agent Doctor** для классификации `FAILED_PRECONDITION`, geo/account eligibility, MCP, hooks, auth, quota и backend failures;
- emergency hosts override с backup и rollback;
- live events через SSE и live sing-box logs;
- CSRF-защита локальных write API;
- GitHub Actions для тестов, Windows/Linux builds и release artifacts.

## Уровень 1 — SAFE MODE

Рекомендуемый первый режим:

```text
Antigravity IDE
      │
      │ process-only HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
      ▼
127.0.0.1:7890
      │
      ▼
   sing-box
      │
      ├── DNS → pinned DoH
      │
      └── outbound → выбранный VPN interface
                         │
                         ▼
                       Google

Fusion 360 / Autodesk / другие приложения
      │
      └──────────────→ обычная системная сеть / VPN
```

Глобальные WinINET/WinHTTP proxy-настройки **не используются**.

## Уровень 2 — AGENT TUNNEL

Используйте его, если вход в аккаунт проходит, но реальная генерация/агент падает. Некоторые helper-процессы IDE могут использовать собственный transport stack и игнорировать proxy environment.

```text
Antigravity.exe
language_server*
agy*
bundled Node helpers
        │
        ▼
    sing-box TUN
        │
        ├── sniff + process matching
        │
        ├── Google/Antigravity DNS → secure DoH
        │
        └── agent-vpn outbound → выбранный VPN interface

остальные процессы
        │
        └── system-direct → обычный системный маршрут
```

Ключевые свойства:

- TUN и local mixed proxy работают в одном экземпляре sing-box;
- `Antigravity.exe`, `language_server*`, `agy*` маршрутизируются через `agent-vpn`;
- generic `node/node.exe` не проксируется глобально: через VPN идут только соединения к Google/Antigravity namespaces;
- private/LAN адреса исключены из TUN auto-route;
- `strict_route=false` по умолчанию, чтобы снизить риск конфликтов с VirtualBox/Fusion/другими desktop-приложениями;
- на Linux включён `auto_redirect`;
- unrelated DNS использует `system-local`, а `*.googleapis.com`, `*.googleusercontent.com`, `antigravity.google` и критичные OAuth/Cloud Code endpoints — secure DoH.

### Права

Windows: запускайте AntigravitiProxi **от имени администратора**, если Agent Tunnel не может создать TUN/маршруты.

Linux: нужны `root` или подходящие capabilities (`CAP_NET_ADMIN`, обычно также `CAP_NET_RAW`).

## Быстрый запуск

Нужен Go 1.23+ для самого проекта.

```bash
git clone https://github.com/Homiakus/AntigravitiProxi.git
cd AntigravitiProxi
go run ./cmd/antigraviti-proxi
```

После запуска откроется `http://127.0.0.1:48765/`.

Без автоматического открытия браузера:

```bash
go run ./cmd/antigraviti-proxi --no-browser
```

## Рекомендуемый сценарий

1. Включить рабочий VPN.
2. Запустить `AntigravitiProxi`.
3. Выбрать VPN-интерфейс, например `AmneziaVPN`.
4. Нажать **Сохранить**.
5. Сначала попробовать **SAFE MODE**.
6. Если регистрация работает, но agent execution падает — перезапустить приложение с нужными правами и нажать **Agent Tunnel + запустить IDE**.
7. Воспроизвести ошибку простым запросом `hello`.
8. Нажать **Agent Doctor** и посмотреть `likely_cause`.

CLI-версия Doctor:

```bash
go run ./cmd/agent-doctor
```

## Сборка

```bash
CGO_ENABLED=0 go build -trimpath -o antigraviti-proxi ./cmd/antigraviti-proxi
```

Windows cross-build:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o antigraviti-proxi-windows-amd64.exe ./cmd/antigraviti-proxi
```

## Почему web UI лёгкий

Web-слой: `net/http + embed + HTML/CSS/vanilla JS + SSE`. Нет Electron, Node.js, npm, React/Vue, отдельного web-сервера, SQLite или CGO.

## Данные приложения

Используется `os.UserConfigDir()`:

- Windows обычно `%LOCALAPPDATA%\AntigravitiProxi`;
- Linux обычно `~/.config/AntigravitiProxi`.

Внутри: `config.json`, `sing-box.json`, логи, `bin/sing-box[.exe]`, `backups/`.

## Безопасность

- UI только на loopback по умолчанию;
- write API требуют SameSite cookie + CSRF header;
- TLS verification не отключается;
- sing-box проверяется по digest официального GitHub Release;
- emergency hosts override выключен по умолчанию;
- global system HTTP proxy не используется;
- Agent Tunnel включается только вручную и остаётся отдельным escalation-уровнем;
- unrelated applications идут через `system-direct`, а не через `agent-vpn`;
- Agent Doctor редактирует обнаруженные bearer/OAuth token values в сниппетах.

Подробнее: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/AGENT_EXECUTION_FAILURE.md`](docs/AGENT_EXECUTION_FAILURE.md), [`MASTER_PLAN.md`](MASTER_PLAN.md).
