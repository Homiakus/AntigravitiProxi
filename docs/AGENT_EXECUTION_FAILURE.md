# Agent execution terminated due to error — диагностика и Agent Tunnel

## Проблема

Целевой сценарий:

1. OAuth / регистрация Antigravity проходит.
2. IDE открывается, аккаунт и модели видны.
3. При реальном запросе агент завершается сообщением `Agent execution terminated due to error`.

Это не самостоятельный код ошибки, а общий UI-симптом. Причина может находиться в transport path, DNS, backend response, account eligibility, MCP/hooks, OAuth refresh или локальном состоянии IDE.

## Транспортная лестница AntigravitiProxi

### Level 1 — SAFE MODE

SAFE MODE остаётся первым и наиболее безопасным режимом:

```text
Antigravity
   │ process-only HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
   ▼
127.0.0.1:7890
   ▼
sing-box mixed inbound
   ▼
secure DoH + selected VPN interface
```

Он не меняет системный HTTP proxy и не создаёт TUN. Это минимизирует влияние на Fusion 360, Autodesk и остальные приложения.

Одновременно launcher:

- удаляет унаследованный `CLOUD_CODE_URL`;
- задаёт `CLOUD_CODE_URL=https://cloudcode-pa.googleapis.com`;
- фиксирует `jetski.cloudCodeUrl` в `settings.json` на production endpoint.

### Level 2 — AGENT TUNNEL

Если регистрация проходит, но agent transport игнорирует proxy environment, используется TUN:

```text
Antigravity.exe / language_server* / agy* / bundled helpers
                         │
                         ▼
                    sing-box TUN
                         │
            process_name / process_path_regex
                         │
                         ▼
                     vpn-direct
                         │ bind_interface
                         ▼
                 selected VPN interface
                         │
                         ▼
                       Google

unrelated traffic
      │
      └──────────────→ system-direct
```

Режим реализован в `internal/proxy/tunnel.go` и управляется из web UI.

## Что реализовано в Agent Tunnel MVP

- Windows + Linux support gate;
- stable `sing-box 1.14.0` как pinned managed runtime;
- автоматическое обновление старого managed `1.13.1` до `1.14.0`;
- SHA-256 digest verification по GitHub Release metadata;
- TUN inbound + local mixed inbound в одном процессе sing-box;
- `auto_route=true`;
- `dns_mode=hijack`;
- `strict_route=false` по умолчанию;
- Linux `auto_redirect=true`;
- process matching через `process_name` и `process_path_regex`;
- отдельный `vpn-direct`, привязанный к выбранному VPN-интерфейсу;
- отдельный `system-direct` для остальных соединений;
- `route.auto_detect_interface=true` для защиты от TUN routing loop;
- secure DoH через выбранный VPN для Antigravity processes и критичных Google namespaces;
- local DNS для unrelated traffic;
- narrow domain fallback для известных Antigravity/Cloud Code endpoints;
- private/LAN/link-local destination exclusion;
- SAFE MODE HTTP/SOCKS proxy остаётся активным как дополнительный слой;
- start / stop / launch API;
- Agent Tunnel card в progressive web UI;
- Agent Doctor в web UI и отдельный `cmd/agent-doctor`;
- unit tests на изоляцию routing policy;
- CI schema-validation реальным pinned sing-box через `sing-box check`.

## Почему sing-box 1.14.0

Agent Tunnel использует TUN `dns_mode`, поэтому проект закреплён на stable `1.14.0`. Конфиг дополнительно проверяется не только Go-тестами структуры JSON, но и настоящим `sing-box check` в CI.

## Process policy

Основные идентификаторы:

```text
Antigravity.exe
antigravity
antigravity-desktop
language_server.exe
language_server_windows_x64.exe
language_server_windows_arm64.exe
language_server_linux_x64
language_server_linux_arm64
language_server
agy.exe
agy
```

Дополнительно применяется `process_path_regex`, чтобы перехватывать bundled helper/Node runtime внутри установки Antigravity, не маршрутизируя глобально любой `node.exe` на машине.

## DNS policy

Для Antigravity-related процессов используются pinned DoH resolvers:

```text
Cloudflare: 1.1.1.1:443 + SNI cloudflare-dns.com
или
Google:     8.8.8.8:443 + SNI dns.google
```

Критичные namespaces включают:

```text
antigravity.google
accounts.google.com
oauth2.googleapis.com
cloudcode-pa.googleapis.com
daily-cloudcode-pa.googleapis.com
*.googleapis.com
```

Остальной DNS остаётся на `local-dns`.

## Важное ограничение изоляции

На Windows стандартный sing-box TUN с `auto_route` получает пакеты на уровне системной маршрутизации, после чего policy отправляет unrelated traffic в `system-direct`. Это намного безопаснее глобального HTTP proxy, но технически не означает, что чужой процесс вообще не проходит через TUN ingress.

Поэтому:

- SAFE MODE остаётся Level 1;
- Agent Tunnel включается только при реальном split-transport симптоме;
- `strict_route=false` остаётся дефолтом;
- для максимальной изоляции Windows будущий P2 backend может использовать более точный WFP/WinDivert process capture;
- на Linux будущий максимальный режим — отдельный network namespace для Antigravity.

## Права

### Windows

TUN и системные маршруты обычно требуют запуск AntigravitiProxi от Administrator.

### Linux

Нужны root либо capabilities, достаточные для TUN/route management, прежде всего `CAP_NET_ADMIN`; для некоторых сценариев также нужен `CAP_NET_RAW`. При `auto_redirect` требуется рабочий nftables/NFQUEUE path.

## Как запускать

1. Включить VPN.
2. Запустить AntigravitiProxi.
3. В web UI выбрать конкретный VPN interface и сохранить.
4. Сначала попробовать **SAFE MODE**.
5. Если OAuth работает, а Agent падает — перезапустить AntigravitiProxi с нужными правами.
6. Нажать **Agent Tunnel + запустить IDE**.
7. В новом пустом диалоге выполнить простой запрос `hello`.
8. Если ошибка остаётся — нажать **Agent Doctor**.

CLI Doctor:

```bash
go run ./cmd/agent-doctor
```

## Диагностическая матрица

| Наблюдение | Вероятный слой | Действие |
|---|---|---|
| OAuth работает, Agent нет, SAFE MODE не помогает | split transport | Agent Tunnel |
| Tunnel исправляет Agent | egress/transport path | оставить Tunnel для Antigravity |
| `FAILED_PRECONDITION` + `User location is not supported` | geo/account/egress | A/B account + egress |
| другой eligible account работает на том же egress | account-side | официальный Google account-country/support flow |
| тот же account работает на другом egress | IP/ASN/egress-side | использовать рабочий egress |
| MCP Error | MCP | отключить MCP и возвращать по одному |
| PreToolUse / hook error | hook / extension | отключить конкретный hook |
| invalid_grant / token refresh | OAuth session | targeted sign-out/re-auth |
| 429 / RESOURCE_EXHAUSTED | quota | quota diagnosis |
| 502 / 503 | backend/transient | retry/backoff/другой model |
| workspaceStorage / extension host | local state | targeted backup/reset |

## Level 3 — eligibility diagnosis

Agent Tunnel исправляет транспорт, но не может менять server-side country/account eligibility.

Нужны два A/B теста:

```text
A: same account + alternate egress
B: alternate eligible account + same egress
```

Интерпретация:

```text
A начинает работать → egress/IP/ASN issue
B начинает работать → account-side eligibility issue
оба не работают     → transport/backend/local state требует дальнейшей диагностики
```

Если backend явно возвращает `User location is not supported`, не следует бесконечно усложнять локальный proxy: Agent Doctor должен зафиксировать Trajectory/Trace ID, а дальнейшее решение зависит от того, egress-side это или server-side account association.

## Инварианты

1. Не включать глобальный WinINET/WinHTTP proxy в штатном режиме.
2. SAFE MODE всегда остаётся первым уровнем.
3. Agent Tunnel включается явно и должен иметь rollback через Stop.
4. Не отключать TLS verification.
5. Не хранить OAuth/bearer tokens в diagnostic output.
6. Production Cloud Code endpoint фиксируется на settings + process-env уровнях.
7. Unrelated traffic не отправляется в `vpn-direct` без совпадения policy.
8. Не обещать локальное исправление server-side account eligibility.

## Следующее усиление

Приоритет после MVP:

- Windows UAC one-click restart;
- Linux capability/nftables preflight;
- реальная TUN health-проверка, а не только mixed-port health;
- PID/process-path → egress verification;
- automatic rollback watchdog;
- stale TUN cleanup после crash;
- dynamic discovery backend hostnames из language-server logs/SNI;
- transport ladder wizard `SAFE MODE → AGENT TUNNEL → ELIGIBILITY DIAGNOSIS`;
- Windows WFP/WinDivert backend для максимально точного process-only transparent capture;
- Linux dedicated network namespace backend.
