# Архитектура AntigravitiProxi

## Цель системы

AntigravitiProxi — локальный кроссплатформенный control plane для диагностируемого и минимально-инвазивного сетевого доступа Antigravity IDE. Проект не должен превращаться в «ещё один глобальный VPN-клиент»: его основной инвариант — **Antigravity получает требуемый маршрут, а посторонние приложения не меняют сетевое поведение без явной причины**.

Подробный анализ отказов и Design FMEA: [`ARCHITECTURE_FMEA.md`](ARCHITECTURE_FMEA.md). Машинно-читаемый реестр рисков: [`../risks/register.json`](../risks/register.json). План работ и Risk IDs связаны в [`../MASTER_PLAN.md`](../MASTER_PLAN.md).

## Архитектурные инварианты

1. **Process isolation.** SAFE MODE не меняет системный proxy; Agent Tunnel обязан доказуемо отделять Antigravity egress от unrelated traffic.
2. **Transport evidence.** Валидная конфигурация не считается доказательством корректного маршрута — нужен runtime egress evidence.
3. **Privilege minimization.** UI, Go control plane и Antigravity IDE должны работать обычным пользователем; привилегии должны быть сосредоточены в минимальном network helper.
4. **Failure containment.** Частичный TUN startup, crash или kill не должны оставлять неидентифицированные routes/nftables/TUN state.
5. **Diagnosis before escalation.** Явный backend/account eligibility reject не должен приводить к бесконечному усилению локального tunnel.
6. **Risk-driven planning.** Незакрытый FMEA risk обязан иметь owner, RPN, mitigation, verification и ссылку из `MASTER_PLAN.md`.

## Слои

```text
┌──────────────────────────────────────────────────────────────┐
│ Embedded PWA                                                │
│ HTML + CSS + vanilla JS + Service Worker                    │
└──────────────────────────┬───────────────────────────────────┘
                           │ loopback HTTP / SSE
┌──────────────────────────▼───────────────────────────────────┐
│ Go control plane — internal/app                              │
│ config / status / actions / CSRF / orchestration / health   │
└──────────┬─────────────────────┬────────────────────┬────────┘
           │                     │                    │
┌──────────▼────────┐  ┌─────────▼────────┐  ┌────────▼────────┐
│ proxy             │  │ diagnostics      │  │ antigravity     │
│ sing-box manager  │  │ DNS / DoH        │  │ launcher        │
│ SAFE proxy        │  │ egress evidence  │  │ endpoint fix    │
│ Agent Tunnel      │  │ Agent Doctor     │  │ hosts fallback  │
└──────────┬────────┘  └──────────────────┘  └─────────────────┘
           │
┌──────────▼───────────────────────────────────────────────────┐
│ sing-box data plane                                         │
│ mixed proxy + TUN + DNS policy + process/path routing       │
└──────────┬────────────────────────────────┬─────────────────┘
           │                                │
           ▼                                ▼
 selected VPN / vpn-direct             system-direct
 Antigravity path                      unrelated apps
```

## Transport ladder

### Level 1 — SAFE MODE

SAFE MODE — основной режим с минимальным blast radius:

```text
Antigravity IDE
      │ process-only HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
      ▼
127.0.0.1:7890 mixed proxy
      ▼
sing-box
      ├── pinned secure DoH
      └── bind_interface → selected VPN

System ENV / WinINET / WinHTTP / unrelated apps: unchanged
```

Он подходит, когда Antigravity и его helper-процессы действительно наследуют proxy environment.

### Level 2 — AGENT TUNNEL

Если OAuth/IDE работают, но внутренний agent transport игнорирует proxy env, включается прозрачный TUN:

```text
Antigravity / language_server / bundled helpers
                 │
                 ▼
          antigravity-tun
                 │
          process/path policy
                 │
                 ▼
             vpn-direct
                 │
             selected VPN

unrelated process
        │
        └──────────────→ system-direct
```

На Linux используется `auto_route + auto_redirect`; process rules расположены **до** TCP `sniff`, потому что в sing-box 1.14 pre-match выполняется до establishment и TCP sniff останавливает pre-match. Linux Agent Tunnel использует строгий TUN capture, после чего unrelated traffic должен быть возвращён через `system-direct`; этот отрицательный инвариант проверяется dual-egress runtime test. На Windows strict routing остаётся более консервативным из-за риска конфликтов с desktop/VM networking.

### Level 3 — ELIGIBILITY DIAGNOSIS

Если runtime egress доказан, а backend возвращает `FAILED_PRECONDITION`, `PERMISSION_DENIED` или другой серверный reject, система не должна продолжать менять сетевые маршруты. Agent Doctor переводит диагностику к account/backend layer.

## Linux data-plane lifecycle

Linux является отдельной архитектурной веткой, а не просто `GOOS=linux` build target.

Перед Agent Tunnel проверяются:

```text
/dev/net/tun
    ↓
managed sing-box version
    ↓
root OR CAP_NET_ADMIN + CAP_NET_RAW
    ↓
selected VPN interface exists + UP
    ↓
sing-box check
    ↓
TUN start
```

Lifecycle:

- `PDEATHSIG=SIGTERM` завершает network helper при исчезновении parent control plane;
- штатная остановка сначала отправляет `SIGTERM`, SIGKILL остаётся только deadline fallback;
- elevated launcher не должен запускать IDE как root и восстанавливает invoking desktop user context;
- CI создаёт реальный Linux network namespace и проверяет создание/cleanup TUN;
- dual-egress test должен доказать `process_name/process_path -> vpn-direct` и negative path `ordinary process -> system-direct`.

## Почему process rules должны идти до sniff

Для TUN в sing-box 1.14 есть pre-match phase. Для TCP до establishment нет payload, поэтому `sniff` в pre-match останавливает дальнейшее сопоставление. Если поставить `sniff` первым, process policy может не стать authoritative до решения kernel/data-plane о пути соединения.

Поэтому порядок для Agent Tunnel:

```text
local mixed route
    ↓
process_name -> vpn-direct
    ↓
process_path_regex -> vpn-direct
    ↓
sniff remaining flows
    ↓
optional domain fallback
    ↓
system-direct final
```

Это не косметическая оптимизация: dual-egress CI был специально добавлен, чтобы ловить подобные расхождения между «валидным JSON» и фактическим source interface.

## DNS

Диагностика использует три независимых источника:

1. системный resolver;
2. Cloudflare DoH с TLS `ServerName=cloudflare-dns.com` и pinned TCP endpoint;
3. Google DoH с TLS `ServerName=dns.google` и pinned TCP endpoint.

В Agent Tunnel Google/Antigravity namespaces направляются в secure DoH; unrelated DNS должен использовать локальный/system resolver. IPv4/IPv6 пока не считаются полностью доказанными независимо — это открытый FMEA риск R-005.

## SOCKS5h

Внутренний SOCKS5 CONNECT test передаёт hostname proxy-серверу как `ATYP=DOMAIN`, то есть проверяет remote DNS аналогично `curl --proxy socks5h://...` и не зависит от потенциально подменённого локального DNS.

## Managed sing-box

Алгоритм:

1. exact pinned managed version;
2. совпадающий system binary допускается только при нужной версии;
3. иначе — официальный GitHub Release asset по GOOS/GOARCH;
4. archive extraction защищён от path traversal;
5. SHA-256 сравнивается с release digest, если metadata его содержит;
6. generated config проверяется реальным `sing-box check` до запуска.

Открытый риск R-023: отсутствие digest должно стать fail-closed, а не warning-only.

## Control plane security

Web UI использует:

- SameSite CSRF cookie + custom header для write API;
- CSP, frame deny, no-sniff и no-referrer headers;
- loopback по умолчанию;
- embedded static files — нет Node/npm/Electron runtime.

Открытый риск R-008: loopback должен стать **enforced invariant**, а не только default setting.

Основные API дополнительно включают Agent Tunnel и Agent Doctor:

- `GET /api/status`
- `GET /api/events`
- `GET /api/diagnostics`
- `GET /api/agent-doctor`
- `GET /api/logs`
- `POST /api/config`
- `POST /api/actions/safe`
- `POST /api/actions/tunnel/start`
- `POST /api/actions/tunnel/stop`
- `POST /api/actions/tunnel/launch`
- `POST /api/actions/endpoint`
- `POST /api/actions/hosts/enable`
- `POST /api/actions/hosts/disable`

## Health model — целевое состояние

Текущее `Running()` нельзя считать окончательным production-health, потому что доступность mixed listener не доказывает работоспособность TUN и правильный egress. Целевая модель:

```text
state = idle | installing | starting | healthy | degraded | stopping | recovering

dimensions:
  mixed_proxy
  tun
  route
  dns_v4
  dns_v6
  egress
  agent_process
  backend
```

`healthy` допускается только когда критичные dimensions имеют runtime evidence. Это R-014/R-015.

## FMEA как часть архитектуры

Design FMEA не является периодическим PDF-отчётом. Он встроен в repository governance:

```text
risks/register.json
       │
       ├── S / O / D / RPN
       ├── owner
       ├── mitigation
       ├── verification
       └── plan_refs
              │
              ▼
       MASTER_PLAN.md
              │
              ▼
       cmd/riskcheck
          ├── CI structural gate
          └── release high/critical gate
```

Порог проекта:

- `RPN >= 150` — high/action-required;
- `Severity >= 9` — release-significant независимо от RPN.

Каждый открытый риск обязан присутствовать в `MASTER_PLAN.md`. Перед release-tag high/critical risk должен быть закрыт либо явно принят с документированной причиной.

Подробная FMEA и архитектурные gates: [`ARCHITECTURE_FMEA.md`](ARCHITECTURE_FMEA.md).
