# Архитектура AntigravitiProxi

## Цель системы

AntigravitiProxi — локальный кроссплатформенный control plane для диагностируемого и минимально-инвазивного сетевого доступа Antigravity IDE. Проект не должен превращаться в «ещё один глобальный VPN-клиент»: основной инвариант — **Antigravity получает требуемый маршрут, а посторонние приложения не меняют сетевое поведение без явной причины**.

Подробный Design FMEA: [`ARCHITECTURE_FMEA.md`](ARCHITECTURE_FMEA.md). Машинно-читаемый источник истины по рискам: [`../risks/register.json`](../risks/register.json). Реализация и Risk IDs связаны в [`../MASTER_PLAN.md`](../MASTER_PLAN.md).

## Архитектурные инварианты

1. **Process isolation.** SAFE MODE не меняет системный proxy; Agent Tunnel обязан отделять Antigravity egress от unrelated traffic и показывать, когда domain fallback ослабляет изоляцию.
2. **Transport evidence.** Валидный JSON не является доказательством маршрута. Нужен runtime evidence: process/PID → socket → sing-box outbound → внешний egress.
3. **Privilege minimization.** UI, Go control plane и Antigravity IDE работают обычным пользователем. Привилегированные действия должны быть bounded и структурированы.
4. **Failure containment.** Частичный TUN startup, crash или kill не должны оставлять неидентифицированные routes/rules/TUN state.
5. **Diagnosis before escalation.** Явный backend/account eligibility reject не должен приводить к бесконечному усилению локального tunnel.
6. **Loopback-only control plane.** Normal-mode HTTP UI, local proxy и observability API не должны слушать LAN/public interfaces.
7. **Risk-driven planning.** Незакрытый FMEA risk обязан иметь owner, RPN, mitigation, verification и ссылку из `MASTER_PLAN.md`.

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
│ managed sing-box data plane                                 │
│ mixed proxy + TUN + DNS policy + process/path routing       │
└──────────┬────────────────────────────────┬─────────────────┘
           │                                │
           ▼                                ▼
 selected VPN / vpn-direct             system-direct
 Antigravity path                      unrelated apps
```

## Transport ladder

### Level 1 — SAFE MODE

```text
Antigravity IDE
      │ process-only HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
      ▼
127.0.0.1:7890 mixed proxy
      ▼
managed sing-box
      ├── secure DoH
      └── bind_interface → selected VPN

System ENV / WinINET / WinHTTP / unrelated apps: unchanged
```

SAFE MODE имеет минимальный blast radius и является первым уровнем.

### Level 2 — AGENT TUNNEL

Если внутренний agent transport игнорирует proxy environment:

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

На Linux канонический capture profile — **`auto_route=true + strict_route=true + auto_redirect=false`**. Это не предпочтение UI, а runtime-evidence инвариант. Dual-egress fixture показал, что при `auto_redirect=true` fallback `ip rule` в текущей topology может уступить системному `main/default` route до того, как TUN process policy увидит локальное соединение.

Process/path rules располагаются **до** TCP `sniff`; иначе pre-match может завершиться до process-aware route decision.

Domain fallback является optional compatibility layer. При его включении система обязана показывать `ISOLATION-RELAXED`; состояние `VERIFIED` не должно скрывать расширенный scope policy.

### Level 3 — ELIGIBILITY DIAGNOSIS

Если runtime egress доказан, а backend возвращает `FAILED_PRECONDITION`, `PERMISSION_DENIED` или другой authoritative server reject, Agent Doctor переводит диагностику к account/backend layer и не предлагает бесконечно менять локальную сеть.

## Linux privilege boundary

Штатная модель:

```text
AntigravitiProxi (desktop user)
        │
        ├── ordinary SAFE MODE
        │
        └── explicit Agent Tunnel start
                  │
                  ▼
          readiness check
          /dev/net/tun + file caps
                  │
          ready ──┴── not ready
                      │
                      ▼
              pkexec / PolicyKit
                      │
          fixed-function internal helper
          ├── verify expected managed path
          ├── reject symlink/unexpected owner
          ├── recheck SHA-256 after elevation
          ├── modprobe tun if required
          ├── install libcap tooling if required
          ├── set exact file capabilities
          └── recheck SHA-256 + capabilities
                      │
                      ▼
              return to user process
```

Helper не принимает произвольную shell command. AntigravitiProxi не читает и не хранит пароль; desktop authentication выполняет ОС. Terminal-attached `sudo` является fallback, если PolicyKit недоступен.

Managed sing-box получает только:

```text
CAP_NET_ADMIN
CAP_NET_RAW
CAP_SYS_PTRACE
CAP_DAC_READ_SEARCH
```

Если приложение уже выполняется как root (например, privileged CI/netns fixture), file capability xattrs не мутируются без необходимости.

## Linux data-plane lifecycle

Перед mutation выполняется:

```text
verified managed sing-box 1.14.0
        ↓
TUN/capability readiness
        ↓
fixed-function PolicyKit bootstrap if required
        ↓
selected VPN interface exists + UP
        ↓
route/rule conflict preflight
        ↓
durable pre-change network journal
        ↓
sing-box check
        ↓
TUN start
        ↓
managed-listener ownership + TUN readiness
        ↓
active journal snapshot
```

Lifecycle controls:

- `PDEATHSIG=SIGTERM` завершает Linux helper при исчезновении parent control plane;
- штатная остановка сначала отправляет `SIGTERM`; kill — только bounded fallback;
- startup failure выполняет stop/wait rollback;
- route table `20229` и rule-priority `19000..19031` зарезервированы как ownership namespace;
- stale-state recovery удаляет только доказуемо owned state;
- повреждённый journal восстанавливается только из валидного `previous-good`, иначе recovery fail-closed;
- elevated launcher не запускает IDE как root и восстанавливает invoking desktop-user context;
- реальный privileged netns CI проверяет TUN lifecycle, dual egress и crash recovery.

## Почему process rules идут до sniff

Порядок route rules:

```text
local mixed -> vpn-direct
    ↓
process_name -> vpn-direct
    ↓
process_path_regex -> vpn-direct
    ↓
sniff remaining flows
    ↓
optional domain fallback -> vpn-direct
    ↓
system-direct final
```

Dual-egress CI является semantic test этого порядка, а не только schema test.

## DNS

Диагностика использует независимые источники:

1. системный resolver;
2. Cloudflare DoH с pinned TCP endpoint и TLS ServerName;
3. Google DoH с pinned TCP endpoint и TLS ServerName.

В Agent Tunnel process-matched Antigravity traffic получает secure DoH через выбранный VPN. Unrelated DNS остаётся на `local-dns`. IPv4/IPv6 и UDP/QUIC ещё не имеют полностью независимой production assurance — R-005 остаётся открытым.

## SOCKS5h

Внутренний SOCKS5 CONNECT test передаёт hostname proxy-серверу как `ATYP=DOMAIN`, то есть проверяет remote DNS аналогично `curl --proxy socks5h://...` и не зависит от локального resolver.

## Managed sing-box и supply chain

Алгоритм Agent Tunnel:

1. exact pinned version `1.14.0`;
2. официальный GitHub Release asset для GOOS/GOARCH;
3. safe archive extraction с path-traversal guard;
4. **официальный SHA-256 digest обязателен** для privileged Agent Tunnel install;
5. archive digest проверяется до extraction;
6. hash установленного binary сохраняется в provenance;
7. повторное использование проверяет installed hash;
8. generated config проверяется реальным `sing-box check`;
9. Linux privilege helper повторно проверяет binary hash после elevation и вокруг `setcap` boundary.

R-023 закрыт: отсутствие или некорректность official digest является fail-closed. Общая совместимость будущих sing-box upgrades, release SBOM/signing остаётся в R-007.

## Control plane security

Normal mode принудительно loopback-only. Это закрытый R-008, а не только default.

Web UI использует:

- SameSite CSRF cookie + custom header для write API;
- CSP, frame deny, no-sniff и no-referrer headers;
- embedded static assets;
- отсутствие Node/npm/Electron runtime;
- write actions только через loopback control plane.

Observability API sing-box также loopback-only и требует отдельный secret.

## Runtime health и assurance

Текущий health уже многомерный: `managed_process`, `mixed_listener_owned`, `tun`, `vpn_interface`, `network_journal`. Порт, который просто принимает TCP, не является доказательством здоровья.

`GET /api/attestation` композиционно проверяет:

```text
process tree
    ↓
live candidate PID
    ↓
socket/source endpoint ownership
    ↓
sing-box connection/outbound
    ↓
vpn-direct
    ↓
external egress evidence
```

UI различает:

```text
assurance = idle | partial | verified | degraded
isolation = inactive | strict | isolation-relaxed
```

External egress evidence имеет bounded in-memory TTL и инвалидируется на start/stop/reconfigure/rollback boundaries.

Открытые части health model: явные transient operation states, независимые `dns_v4/dns_v6`, UDP/QUIC и authoritative backend health classification — R-005/R-011/R-014/R-015.

## Основные API

- `GET /api/status`
- `GET /api/events`
- `GET /api/diagnostics`
- `GET /api/agent-doctor`
- `GET /api/attestation`
- `GET /api/logs`
- `POST /api/config`
- `POST /api/actions/safe`
- `POST /api/actions/tunnel/start`
- `POST /api/actions/tunnel/stop`
- `POST /api/actions/tunnel/launch`
- `POST /api/actions/endpoint`
- `POST /api/actions/hosts/enable`
- `POST /api/actions/hosts/disable`

## FMEA как часть архитектуры

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
