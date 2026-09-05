# Agent execution terminated due to error — диагностика и Agent Tunnel

## Проблема

Целевой сценарий:

1. OAuth / регистрация Antigravity проходит.
2. IDE открывается, аккаунт и модели видны.
3. При реальном запросе агент завершается сообщением `Agent execution terminated due to error`.

Это общий UI-симптом, а не самостоятельный root cause. Ошибка может находиться в transport path, DNS, backend response, account eligibility, MCP/hooks, OAuth refresh или локальном состоянии IDE.

## Транспортная лестница

### Level 1 — SAFE MODE

```text
Antigravity
   │ process-only HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
   ▼
127.0.0.1:7890
   ▼
managed sing-box mixed inbound
   ▼
secure DoH + selected VPN interface
```

SAFE MODE не меняет системный HTTP proxy и не создаёт TUN. Это минимальный blast radius для Fusion 360, Autodesk и остальных приложений.

Launcher одновременно:

- удаляет унаследованный `CLOUD_CODE_URL`;
- задаёт `CLOUD_CODE_URL=https://cloudcode-pa.googleapis.com`;
- фиксирует `jetski.cloudCodeUrl` на production endpoint.

### Level 2 — AGENT TUNNEL

Если agent transport игнорирует proxy environment:

```text
Antigravity / language_server / bundled helpers
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

unrelated traffic
      │
      └──────────────→ system-direct
```

Режим реализован в `internal/proxy/tunnel.go` и управляется из web UI.

## Текущее состояние Agent Tunnel

Реализовано:

- Windows + Linux support gate;
- pinned stable `sing-box 1.14.0`;
- migration старого managed `1.13.1` → `1.14.0`;
- fail-closed official SHA-256 digest verification для privileged install;
- installed-binary hash + persistent provenance;
- TUN inbound + local mixed inbound в одном процессе;
- `auto_route=true`;
- `dns_mode=hijack`;
- Linux `strict_route=true` как enforced invariant;
- Linux `auto_redirect=false` после real dual-egress evidence;
- process matching через `process_name` и `process_path_regex`;
- отдельные `vpn-direct` и `system-direct`;
- `route.auto_detect_interface=true` для защиты от routing loop;
- secure DoH через выбранный VPN для Antigravity process policy;
- local DNS для unrelated traffic;
- optional domain fallback с явным `ISOLATION-RELAXED` состоянием;
- private/LAN/link-local destination exclusion;
- start / stop / launch API;
- one-click Linux privilege preparation;
- Agent Doctor в web UI и `cmd/agent-doctor`;
- evidence-based health;
- `GET /api/attestation` + UI Runtime network assurance;
- durable Linux network journal + conservative stale recovery;
- PID/socket → sing-box outbound → external-egress proof на Linux;
- native Windows exact local endpoint → PID attribution fixture;
- real Linux TUN/dual-egress/crash-recovery CI.

## Почему sing-box 1.14.0

Agent Tunnel использует TUN `dns_mode` и runtime observability API, поэтому project contract закреплён на 1.14.0. Generated config проходит настоящий `sing-box check` в CI. Privileged installer не продолжает работу без валидного official SHA-256 evidence.

## Linux routing profile

Канонический профиль:

```text
auto_route=true
strict_route=true
auto_redirect=false
```

Dual-egress runtime fixture показал, что `auto_redirect=true` в текущей topology может оставить локальному system default route возможность обойти process-aware TUN decision. Поэтому `auto_redirect=false` — evidence-backed invariant, а не временная настройка.

Route-rule order:

```text
local mixed -> vpn-direct
process_name -> vpn-direct
process_path_regex -> vpn-direct
sniff remaining traffic
optional domain fallback -> vpn-direct
system-direct final
```

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

`process_path_regex` ловит bundled helper/Node runtime внутри Antigravity installation path, не маршрутизируя глобально любой `node` на машине.

## DNS policy

Для Antigravity process policy используются pinned DoH resolvers:

```text
Cloudflare: 1.1.1.1:443 + SNI cloudflare-dns.com
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

Domain fallback выключаем/включаем отдельно от process matching. При включённом fallback unrelated Google client потенциально может попасть в broader policy, поэтому UI не скрывает это под зелёным transport status и показывает `ISOLATION-RELAXED`.

## Права

### Linux

Нормальный запуск — обычным пользователем. При первом явном Agent Tunnel start приложение само проверяет TUN/capabilities и, если нужно, вызывает один fixed-function internal helper через PolicyKit (`pkexec`). Helper повторно проверяет managed binary, при необходимости загружает TUN/install libcap tooling и выдаёт только:

```text
CAP_NET_ADMIN
CAP_NET_RAW
CAP_SYS_PTRACE
CAP_DAC_READ_SEARCH
```

AntigravitiProxi не читает и не хранит password. OS authentication dialog управляется PolicyKit. Terminal-attached `sudo` — только fallback.

### Windows

Текущему Agent Tunnel для TUN/route mutations всё ещё может потребоваться запуск AntigravitiProxi от Administrator. Linux-equivalent minimal UAC helper остаётся открытым P1/R-006 пунктом.

## Как запускать

1. Включить VPN.
2. Запустить AntigravitiProxi обычным пользователем.
3. Выбрать/подтвердить конкретный VPN interface.
4. Сначала попробовать **SAFE MODE**.
5. Если OAuth работает, а Agent падает — нажать **«Подготовить Tunnel и запустить IDE»**.
6. На Linux при необходимости подтвердить один PolicyKit dialog.
7. В новом диалоге выполнить простой запрос `hello`.
8. Проверить **Runtime network assurance**, а не только `Tunnel ACTIVE`.
9. Если transport доказан, но ошибка остаётся — запустить **Agent Doctor**.

CLI Doctor:

```bash
go run ./cmd/agent-doctor
```

## Runtime network assurance

`GET /api/attestation` и UI проверяют цепочку:

```text
Antigravity process tree
    ↓
active candidate PID
    ↓
live socket/source endpoint ownership
    ↓
sing-box connection tracker
    ↓
vpn-direct outbound
    ↓
external egress evidence
```

Состояния transport:

```text
idle | partial | verified | degraded
```

Состояния isolation выводятся отдельно:

```text
inactive | strict | isolation-relaxed
```

External-egress evidence имеет bounded TTL и инвалидируется на start/stop/reconfigure/rollback boundary. Поэтому старое egress evidence не должно пережить контролируемую смену data plane.

## Диагностическая матрица

| Наблюдение | Вероятный слой | Действие |
|---|---|---|
| OAuth работает, Agent нет, SAFE MODE не помогает | split transport | Agent Tunnel |
| Tunnel + assurance исправляет Agent | egress/transport path | оставить Tunnel для Antigravity |
| Tunnel `VERIFIED`, но backend `FAILED_PRECONDITION` | backend/account | Agent Doctor / eligibility diagnosis |
| `User location is not supported` | geo/account/egress | A/B account + egress |
| другой eligible account работает на том же egress | account-side | официальный account/support flow |
| тот же account работает на другом egress | IP/ASN/egress-side | использовать рабочий egress |
| MCP Error | MCP | отключить MCP и возвращать по одному |
| PreToolUse / hook error | hook / extension | отключить конкретный hook |
| invalid_grant / token refresh | OAuth session | targeted sign-out/re-auth |
| 429 / RESOURCE_EXHAUSTED | quota | quota diagnosis |
| 502 / 503 | backend/transient | retry/backoff/другой model |
| workspaceStorage / extension host | local state | targeted backup/reset |

## Level 3 — eligibility diagnosis

Agent Tunnel исправляет transport, но не может менять server-side country/account eligibility.

A/B:

```text
A: same account + alternate egress
B: alternate eligible account + same egress
```

Интерпретация:

```text
A работает → egress/IP/ASN issue
B работает → account-side eligibility issue
оба нет    → transport/backend/local state требует дальнейшей диагностики
```

Authoritative server-side reject не должен приводить к ещё более широкому local routing policy.

## Инварианты

1. Не включать глобальный WinINET/WinHTTP proxy в штатном режиме.
2. SAFE MODE остаётся первым уровнем.
3. Agent Tunnel включается явно и должен иметь rollback.
4. Не отключать TLS verification.
5. Не хранить OAuth/bearer tokens в diagnostic output.
6. Production Cloud Code endpoint фиксируется на settings + process-env уровнях.
7. Unrelated traffic не отправляется в `vpn-direct` без policy match; domain fallback отдельно обозначается как relaxed isolation.
8. `ACTIVE` не эквивалентен `VERIFIED`.
9. Не обещать локальное исправление server-side account eligibility.

## Следующее усиление

Открытые приоритеты:

- Windows minimal UAC helper без elevation всего control plane;
- full Windows Agent Tunnel PID/socket → sing-box outbound → controlled external-egress proof;
- Windows exact route ownership/recovery через interface LUID/route compartment;
- explicit transient operation state machine + cancellable operation IDs;
- independent IPv4/IPv6 + DNS + UDP/QUIC assurance;
- dynamic helper/endpoint learning с reviewed policy promotion;
- замена broad domain fallback на learned process+endpoint routing;
- distro/ARM64/Docker/VM runtime matrix;
- centralized diagnostic redaction + support bundle;
- release SBOM/provenance/signing.
