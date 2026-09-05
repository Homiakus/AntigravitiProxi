# AntigravitiProxi

Кроссплатформенный Go control plane для сетевого транспорта Antigravity IDE на Windows и Linux. Проект вырос из `Antigravity-Proxy-Manager-v5.ps1`, но текущая архитектура уже не является прямым портом PowerShell: она разделяет минимально-инвазивный SAFE MODE, прозрачный Agent Tunnel, runtime assurance и диагностику backend/account failures.

Главный инвариант: **Antigravity получает требуемый маршрут, а системный HTTP proxy и сетевое поведение посторонних приложений не меняются без явной причины**.

## Транспортная лестница

1. **SAFE MODE** — process-only `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY` через локальный mixed proxy. WinINET/WinHTTP и глобальный proxy не меняются.
2. **AGENT TUNNEL** — sing-box TUN с process/path-aware policy для helper-процессов, которые игнорируют proxy environment.
3. **ELIGIBILITY DIAGNOSIS** — если transport доказан, но backend возвращает `FAILED_PRECONDITION`, `PERMISSION_DENIED`, geo/account reject и т.п., Agent Doctor прекращает бессмысленную эскалацию локальной сети и переводит диагностику на backend/account слой.

## Что реализовано

- один Go-проект без Electron/Node/npm/React/Vue;
- embedded responsive PWA на `net/http + embed + HTML/CSS/vanilla JS + SSE`;
- loopback control plane `127.0.0.1:48765`;
- local mixed proxy `127.0.0.1:7890`;
- pinned managed `sing-box 1.14.0`;
- fail-closed SHA-256 verification официального release asset и persistent provenance;
- Cloudflare/Google DoH;
- явный `bind_interface` к выбранному VPN;
- автоматическое обнаружение вероятных VPN-интерфейсов;
- SAFE MODE с process-only launch environment;
- Agent Tunnel с `process_name` + `process_path_regex`;
- `vpn-direct` для Antigravity path и `system-direct` для unrelated traffic;
- Linux capture profile: `auto_route=true`, `strict_route=true`, `auto_redirect=false`;
- secure DoH для Antigravity/Google policy и `local-dns` для unrelated DNS;
- optional domain fallback, который UI явно помечает как `ISOLATION-RELAXED`;
- Agent Doctor CLI + web API;
- runtime health и composed assurance через `GET /api/attestation`;
- PID/socket → sing-box outbound → external-egress evidence;
- transactional Linux startup/rollback и durable network-state journal;
- stale-state recovery с conservative ownership policy;
- responsive UI с отдельными SAFE MODE, Agent Tunnel, setup status и Runtime network assurance;
- FMEA risk register + `riskcheck` CI/release gate.

## SAFE MODE

```text
Antigravity IDE
      │ process-only proxy env
      ▼
127.0.0.1:7890
      ▼
managed sing-box
      ├── DoH
      └── bind_interface → selected VPN

WinINET / WinHTTP / global HTTP proxy: unchanged
Fusion 360 / Autodesk / unrelated apps: unchanged
```

SAFE MODE — рекомендуемый первый уровень.

## AGENT TUNNEL

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
                 ▼
          selected VPN

unrelated process
        │
        └──────────────→ system-direct
```

На Linux используется `auto_route + strict_route` при `auto_redirect=false`. Это зафиксированный runtime-evidence инвариант: dual-egress CI показал, что `auto_redirect=true` в текущей topology может позволить локальному default route обойти process-aware TUN policy до того, как sing-box увидит процесс.

Process/path rules идут до `sniff`. Domain fallback является дополнительным compatibility-механизмом и не маскируется под строгую process isolation: при его включении assurance/UI показывает `ISOLATION-RELAXED`.

## Права

### Linux

Штатный запуск выполняется **обычным пользователем**:

```bash
go run ./cmd/antigraviti-proxi
```

При первом запуске Agent Tunnel AntigravitiProxi автоматически:

1. проверяет/устанавливает hash-verified managed sing-box;
2. проверяет `/dev/net/tun`;
3. проверяет file capabilities;
4. если требуется, вызывает **один fixed-function internal helper** через PolicyKit (`pkexec`), а при интерактивном terminal fallback — через `sudo`;
5. helper повторно проверяет путь/ownership/SHA-256 managed binary;
6. при необходимости загружает `tun`, устанавливает libcap tooling и выдаёт только:
   `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`;
7. повторно проверяет capabilities и только после этого продолжает Agent Tunnel startup.

Пароль приложение не читает, не хранит и не прокидывает через stdin. Авторизацию выполняет ОС. После замены managed sing-box потерянные file capabilities обнаруживаются и восстанавливаются тем же bounded helper flow при следующем явном запуске Agent Tunnel.

Подробнее: [`docs/LINUX_PRIVILEGE_BOOTSTRAP.md`](docs/LINUX_PRIVILEGE_BOOTSTRAP.md) и [`docs/LINUX.md`](docs/LINUX.md).

### Windows

Agent Tunnel поддерживается, но полноценный minimal UAC helper ещё не завершён: для TUN/route operations сейчас может потребоваться запуск AntigravitiProxi от Administrator. Это остаётся открытым P1/R-006 пунктом и не должно описываться как уже решённая Linux-equivalent privilege model.

## Быстрый запуск

Нужен Go 1.23+:

```bash
git clone https://github.com/Homiakus/AntigravitiProxi.git
cd AntigravitiProxi
go run ./cmd/antigraviti-proxi
```

UI откроется на:

```text
http://127.0.0.1:48765/
```

Без автоматического открытия браузера:

```bash
go run ./cmd/antigraviti-proxi --no-browser
```

## Рекомендуемый сценарий

1. Подключить рабочий VPN.
2. Запустить AntigravitiProxi обычным пользователем.
3. Выбрать VPN-интерфейс; если найден ровно один подходящий кандидат, UI может выбрать его автоматически.
4. Сначала запустить **SAFE MODE**.
5. Если OAuth/IDE работают, а agent execution падает — нажать **«Подготовить Tunnel и запустить IDE»**.
6. На Linux при необходимости подтвердить один системный PolicyKit-диалог.
7. После запуска смотреть не только `ACTIVE`, а блок **Runtime network assurance**: `Assurance`, `Isolation`, `PID route`, `External egress`, `Evidence age`.
8. Если transport доказан, но Agent всё равно падает — запустить **Agent Doctor**.

CLI Doctor:

```bash
go run ./cmd/agent-doctor
```

## Runtime assurance

`GET /api/attestation` и UI разделяют:

- состояние transport (`idle/partial/verified/degraded`);
- strict vs `isolation-relaxed` policy;
- discovered Antigravity PID tree;
- PID/socket ownership;
- sing-box connection/outbound evidence;
- внешний egress;
- свежесть/cached TTL evidence.

Открытый локальный порт сам по себе не считается доказательством здоровья: listener должен принадлежать managed sing-box PID, а Agent Tunnel должен иметь TUN/VPN/journal/runtime evidence.

## Сборка

```bash
CGO_ENABLED=0 go build -trimpath -o antigraviti-proxi ./cmd/antigraviti-proxi
```

Windows cross-build:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o antigraviti-proxi-windows-amd64.exe ./cmd/antigraviti-proxi
```

## Безопасность

- control plane и local proxy в normal mode принудительно loopback-only;
- write API требуют SameSite cookie + CSRF header;
- TLS verification не отключается;
- privileged Agent Tunnel installer fail-closed при отсутствии валидного SHA-256 evidence;
- Linux privilege bootstrap не принимает произвольные команды и повторно проверяет managed binary после elevation;
- global WinINET/WinHTTP proxy не используется;
- emergency hosts override выключен по умолчанию;
- domain fallback всегда видим как ослабление isolation;
- diagnostic/assurance архитектура не должна путать transport success с server-side account eligibility.

## Документация

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — архитектурные инварианты и data plane;
- [`docs/LINUX.md`](docs/LINUX.md) — Linux эксплуатация;
- [`docs/LINUX_PRIVILEGE_BOOTSTRAP.md`](docs/LINUX_PRIVILEGE_BOOTSTRAP.md) — privilege boundary;
- [`docs/AGENT_EXECUTION_FAILURE.md`](docs/AGENT_EXECUTION_FAILURE.md) — transport/eligibility диагностика;
- [`docs/ARCHITECTURE_FMEA.md`](docs/ARCHITECTURE_FMEA.md) — Design FMEA;
- [`risks/register.json`](risks/register.json) — machine-readable risk source of truth;
- [`MASTER_PLAN.md`](MASTER_PLAN.md) — реализация и risk-to-plan tracking.
