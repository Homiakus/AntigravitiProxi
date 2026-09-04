# Agent execution terminated due to error — исследование и архитектура решения

## Контекст

Сценарий, который требуется закрыть в AntigravitiProxi:

1. OAuth / регистрация Antigravity проходит.
2. IDE открывается и аккаунт распознаётся.
3. При первом или последующих запросах Agent завершается сообщением `Agent execution terminated due to error`.

Это **не одна ошибка**, а общий UI-симптом. Реальная причина находится в `ls-main.log`, language-server/agent logs, MCP/hook logs или backend response.

## Что показывает исследование

### 1. Process-only HTTP_PROXY недостаточен как единственный механизм

Текущий SAFE MODE передаёт `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` только процессу Antigravity и его потомкам. Это безопасно для Fusion 360, но не гарантирует перехват всех transport paths.

Antigravity использует несколько процессов/сетевых клиентов: IDE, language server, `node.exe`, agent harness, CLI-compatible Cloud Code path. Любой из них может:

- открыть сокет напрямую;
- использовать библиотеку, которая не читает `HTTP_PROXY`;
- использовать отдельный Cloud Code endpoint override;
- использовать UDP/QUIC;
- унаследовать старый `CLOUD_CODE_URL`;
- разрешить DNS вне локального proxy.

Поэтому OAuth может работать, а generation path — уходить другим маршрутом.

### 2. Отдельно существует серверный geo/account слой

Характерная запись:

```text
FAILED_PRECONDITION (code 400): User location is not supported for the API use.
```

Она встречается даже тогда, когда логин и получение списка моделей проходят успешно.

Нужно различать два разных случая:

- **egress-side**: один и тот же аккаунт работает через один IP/ASN и не работает через другой;
- **account-side**: один аккаунт стабильно не работает, а другой на том же компьютере/маршруте работает.

Локальный proxy способен исправить только первый случай. Серверный country association / eligibility локально изменить нельзя.

### 3. Старый `CLOUD_CODE_URL` способен пережить настройку IDE

Antigravity/agy имеет Cloud Code endpoint override. Поэтому одной записи `jetski.cloudCodeUrl` в `settings.json` недостаточно, если процесс наследует `CLOUD_CODE_URL` из окружения.

SAFE MODE теперь обязан:

1. удалить унаследованный `CLOUD_CODE_URL`;
2. добавить:

```text
CLOUD_CODE_URL=https://cloudcode-pa.googleapis.com
```

3. параллельно оставить `jetski.cloudCodeUrl` на production endpoint.

Это реализовано в `internal/antigravity/antigravity.go`.

## Диагностическая матрица

| Наблюдение | Наиболее вероятный слой | Действие |
|---|---|---|
| `FAILED_PRECONDITION` + `User location is not supported` | geo / account / egress | A/B account + IP, Agent Tunnel |
| Claude работает, Gemini нет | Gemini backend / geo | проверить egress и account association |
| другой аккаунт работает на том же ПК | account-side | официальный account-country/support flow |
| тот же аккаунт работает через другой exit | egress-side | менять маршрут / Agent Tunnel |
| MCP Error | MCP | отключить MCP и включать по одному |
| PreToolUse / hook error | hook / extension | отключить конкретный hook/extension |
| `workspaceStorage` / extension host | local state | targeted backup/reset |
| 429 / RESOURCE_EXHAUSTED | quota | quota diagnosis |
| 502 / 503 | backend/transient | retry/backoff + latest IDE |
| OAuth работает, agent нет, proxy tests зелёные | split transport | Transparent Agent Tunnel |

## Решение уровня P1: Agent Tunnel

### Задача

Перехватывать **весь сетевой трафик Antigravity-related процессов**, даже если конкретный runtime игнорирует proxy environment, при этом не переводить Fusion 360 и остальные приложения на HTTP proxy.

### Windows

Основной backend — `sing-box TUN` с process-aware routing.

Целевые процессы:

```text
Antigravity.exe
Antigravity IDE.exe
language_server.exe
language_server_windows.exe
language_server_windows_x64.exe
agy.exe
node.exe
```

Концепция:

```text
Antigravity / language_server / node
            │
            ▼
      sing-box TUN
            │
     process_name rule
            │
            ▼
    selected VPN interface
            │
         Google

Fusion 360 / Autodesk
            │
       direct/bypass
            │
      normal network
```

`sing-box` поддерживает `process_name`, `process_path` и `process_path_regex` на Windows/Linux/macOS для TUN route rules.

#### Почему не DLL injection как основной backend

Winsock hooking работает точечно, но остаётся зависимым от:

- конкретных API (`connect`, `ConnectEx`, DNS hooks и т.д.);
- изменений Antigravity;
- дочерних процессов;
- антивирусов/EDR;
- UDP/QUIC;
- ABI и архитектуры.

Он может быть добавлен как Windows fallback, но TUN является более полным транспортным слоем.

### Linux

Два режима:

1. `sing-box TUN + process rules` — простой общий backend;
2. dedicated network namespace для Antigravity — максимальная изоляция, чтобы остальные процессы пользователя вообще не заходили в TUN.

Целевая архитектура Linux P2:

```text
host namespace
  ├── Firefox/Fusion-equivalent/etc → normal route
  └── Antigravity launcher
          ↓
     dedicated netns
          ↓
       sing-box
          ↓
      VPN interface
```

## Egress integrity

Agent Tunnel должен проверять **именно agent path**, а не только браузерный IP.

Минимальные probes:

```text
antigravity.google
oauth2.googleapis.com
cloudcode-pa.googleapis.com
daily-cloudcode-pa.googleapis.com
generativelanguage.googleapis.com
www.googleapis.com
```

Для каждого пути фиксировать:

- DNS A/AAAA;
- selected interface;
- source IP;
- remote IP;
- TLS result;
- HTTP result;
- proxy/TUN mode;
- process responsible for connection (где доступно).

## Account-vs-egress A/B диагностика

В UI нужен отдельный wizard.

### Test A — same account, alternate egress

Если аккаунт начинает работать на другом стабильном exit, проблема транспортная/IP/ASN.

### Test B — alternate account, same egress

Если другой eligible account работает на том же exit, проблема account-side.

### Test C — Antigravity CLI canary

CLI использует общий agent harness и позволяет отделить IDE-local state от backend/account/network.

Результаты:

```text
IDE fail + CLI fail  -> backend/account/egress
IDE fail + CLI works -> IDE state / IDE transport / extension/MCP
```

## Локальное состояние

Полный wipe профиля не должен быть первым шагом. Нужен targeted reset с backup:

1. workspaceStorage конкретного workspace;
2. `User/globalStorage/google.antigravity`;
3. CachedData / Cache / Code Cache / GPUCache;
4. extension state;
5. OAuth только если doctor нашёл auth signature.

## Agent Doctor

Уже реализован:

```bash
go run ./cmd/agent-doctor
```

Doctor классифицирует:

- geo/eligibility;
- account permission;
- MCP;
- hooks;
- auth refresh;
- quota;
- capacity/backend errors;
- workspace/extension state;
- generic termination.

Следующий этап — встроить Doctor в web UI и связать findings с автоматическими repair actions.

## Приоритет реализации

### P1.0 — немедленно

- [x] Agent Doctor CLI.
- [x] sanitize inherited `CLOUD_CODE_URL`.
- [x] force `CLOUD_CODE_URL=https://cloudcode-pa.googleapis.com` for child process.
- [ ] добавить `generativelanguage.googleapis.com` и `www.googleapis.com` в web diagnostics.
- [ ] Agent Doctor panel в web UI.

### P1.1 — Agent Tunnel MVP

- [ ] отдельный `agent-tun.json` generator;
- [ ] Windows/Linux TUN launch;
- [ ] process rules for Antigravity/language_server/node/agy;
- [ ] explicit Autodesk/Fusion bypass presets;
- [ ] privileged helper;
- [ ] start/stop rollback of routes;
- [ ] health check after tunnel startup;
- [ ] SAFE MODE fallback: ENV proxy → if agent transport leak detected → Agent Tunnel.

### P1.2 — adaptive diagnosis

- [ ] parse latest `ls-main.log` after failed run;
- [ ] classify account-side vs egress-side;
- [ ] CLI canary;
- [ ] per-model A/B test;
- [ ] egress/ASN fingerprint;
- [ ] trajectory/error ID extraction in web UI;
- [ ] exportable redacted diagnostic bundle.

## Инварианты

1. Не менять глобальный HTTP proxy Windows/Linux в штатном режиме.
2. Не ломать Fusion 360/Autodesk ради Antigravity.
3. Любая privileged network modification имеет rollback.
4. Никакого отключения TLS verification.
5. Не хранить OAuth tokens в diagnostic bundle.
6. Не обещать исправление server-side account eligibility локальными действиями.
7. Production Cloud Code endpoint должен быть однозначным на settings + process env уровнях.
