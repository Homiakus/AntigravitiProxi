# Архитектурный аудит и Design FMEA — AntigravitiProxi

Дата базовой оценки: 2026-09-04.

Этот документ описывает архитектурные риски системы, а `risks/register.json` является машинно-читаемым источником истины по их текущим статусам и баллам. `MASTER_PLAN.md` обязан содержать каждый незакрытый Risk ID; это автоматически проверяет `cmd/riskcheck`.

## 1. Граница системы

AntigravitiProxi состоит из четырёх принципиально разных зон ответственности:

```text
Embedded Web UI / PWA
        │
        │ HTTP + SSE on loopback
        ▼
Go control plane (`internal/app`)
        │
        ├── settings / orchestration / diagnostics
        ├── Antigravity launcher / Agent Doctor
        └── privileged network-helper lifecycle
                     │
                     ▼
                 sing-box
        mixed proxy + TUN + DNS + route policy
                     │
         ┌───────────┴────────────┐
         ▼                        ▼
 selected VPN interface       system-direct
 Antigravity path             unrelated apps
```

Главная архитектурная цель — не «сделать глобальный VPN», а обеспечить следующий инвариант:

> **Трафик Antigravity, требующий специального egress, должен доказуемо идти через выбранный VPN; остальные процессы не должны менять маршрут из-за AntigravitiProxi.**

Второй инвариант:

> **Ошибка transport-plane не должна ошибочно трактоваться как серверная account/geo проблема и наоборот.**

Третий инвариант:

> **Привилегированный сетевой helper не должен превращать весь desktop control plane и Antigravity IDE в root/Administrator-процессы без необходимости.**

## 2. Сильные архитектурные решения

### 2.1 Разделение SAFE MODE и Agent Tunnel

Это правильное эшелонирование сложности:

- SAFE MODE не меняет системные маршруты и является минимально-инвазивным первым шагом;
- Agent Tunnel применяется только когда внутренний transport IDE игнорирует process proxy;
- серверная eligibility диагностика находится ещё выше и не должна «лечиться» бесконечным усложнением локальной сети.

Это снижает blast radius по сравнению с глобальным WinINET/WinHTTP/system proxy.

### 2.2 Внешний data plane изолирован в sing-box

Go-код не реализует собственный TUN/TCP/IP stack. Он отвечает за policy/config/lifecycle, а data plane делегирован специализированному движку. Это существенно сокращает объём критического низкоуровневого кода.

### 2.3 Детерминированная зависимость

Положительные меры:

- pin конкретной версии sing-box;
- проверка SHA-256 release digest, когда он опубликован;
- проверка реальным `sing-box check`;
- Linux privileged runtime test с настоящим TUN.

Остаётся R-023: отсутствие digest сейчас должно стать fail-closed, а не warning-only.

### 2.4 Linux lifecycle уже проверяется runtime-тестом

CI не ограничивается cross-compile. Он создаёт network namespace, реальный TUN, nftables/auto_redirect state и проверяет cleanup. Это намного сильнее обычного unit/golden test.

### 2.5 Linux root-context риск уже частично устранён

Если control plane запущен через sudo/pkexec, launcher пытается восстановить исходного desktop user, HOME/XDG/DBus context и не запускать IDE как root. Архитектурно правильнее всё равно перейти к отдельному минимальному privileged helper — R-006.

## 3. Главные слепые зоны

### 3.1 «Config is correct» не равно «egress is correct»

До dual-egress runtime теста система доказывала, что sing-box принимает конфигурацию и создаёт TUN, но не доказывала фактический источник трафика конкретного процесса. Это риск R-015 и связанный R-002.

Нужны два уровня доказательства:

1. CI: синтетические процессы с разными именами/путями дают разные source IP через два физических egress интерфейса;
2. production health: безопасный probe подтверждает выбранный egress для реально обнаруженного PID tree Antigravity.

### 3.2 Process-aware policy зависит от внешней топологии IDE

Antigravity может добавлять/переименовывать helper-процессы. Статический список не может считаться окончательным контрактом. Поэтому process matcher должен эволюционировать к модели:

```text
known process names
      +
known install-path families
      +
runtime PID tree discovery
      +
observed backend/SNI/log evidence
      ↓
reviewed learned policy
```

Это R-002 и R-020.

### 3.3 Domain fallback ослабляет изоляцию

Domain-only fallback нужен как аварийная страховка, но правило `*.googleapis.com -> vpn-direct` потенциально меняет маршрут для не-Antigravity процесса, если его трафик попал в TUN. Это R-003.

Правильная конечная архитектура — процесс/путь как первичный scope, endpoint как дополнительный признак, а broad fallback должен явно переводить состояние в `degraded/isolation-relaxed`.

### 3.4 Health model пока слишком бинарный

Проверка mixed-port не доказывает:

- наличие корректного TUN;
- ownership маршрутов;
- secure DNS path;
- правильный egress;
- работу agent process;
- отсутствие server-side eligibility rejection.

Поэтому `running=true` недостаточно. Нужен health vector:

```text
mixed_proxy
tun
route
dns_v4
dns_v6
egress
agent_process
backend
```

И итоговая агрегация `healthy/degraded/failed`, R-014.

### 3.5 Применение сетевых изменений не транзакционно

Старт TUN — это многошаговая операция. Любая ошибка между фазами может оставить часть состояния. Нужны:

```text
capture baseline
    ↓
apply phase 1
    ↓
verify
    ↓
apply phase 2
    ↓
verify
    ↓
commit ownership record

on any failure:
rollback in reverse order
verify baseline restored
```

Это R-001/R-010/R-016.

### 3.6 Privilege boundary пока не завершён

Идеальная граница:

```text
Web UI + Go orchestration     ordinary user
Antigravity IDE              ordinary user
Diagnostics                  ordinary user
Privileged network helper    minimal API only
sing-box TUN                 required caps/admin only
```

Helper должен принимать только структурированные операции вида `start_tunnel(config_hash)`, `stop_owned_tunnel(operation_id)`, `read_owned_state()`, а не произвольные команды. R-006.

### 3.7 Настройки, UI и runtime policy могут рассинхронизироваться

Наличие поля в `Settings` ещё не доказывает, что оно реально влияет на `StartAgentTunnel`. Нужен один типизированный validated options object и contract tests `API -> persisted settings -> generated sing-box config`. R-021.

### 3.8 Branch protection отсутствует

CI может быть очень сильным, но при незащищённом `main` он остаётся наблюдателем, а не gate. Это process-FMEA риск R-017.

## 4. Метод FMEA

Используется классическая Design FMEA модель:

- **Severity (S)** — тяжесть эффекта, 1..10;
- **Occurrence (O)** — вероятность/частота возникновения, 1..10;
- **Detection (D)** — трудность обнаружения до ущерба; 10 означает плохо обнаруживаемый риск;
- **RPN = S × O × D**.

Для проекта установлен рабочий порог:

- `RPN >= 150` — high/action-required;
- `Severity >= 9` — release-significant независимо от RPN.

Важно: RPN не заменяет инженерное решение. Например риск S=10 может иметь умеренный RPN после улучшения detection, но всё равно требует явного release review.

Баллы — не статистическая истина. Они являются инженерной оценкой и должны изменяться после runtime evidence, incident data и fault-injection результатов.

## 5. Текущая FMEA-приоритизация

Полная таблица находится в `risks/register.json`. На архитектурном уровне приоритеты следующие.

| Risk | Failure mode | Current RPN | Почему важен |
|---|---|---:|---|
| R-020 | backend endpoint topology drift | 210 | внешний API/IDE меняется независимо от клиента |
| R-013 | route/nftables conflict with Docker/VM/NM | 200 | высокий blast radius для всего desktop host |
| R-014 | false-positive health from mixed port | 200 | система может сообщать успех при неверном agent egress |
| R-005 | IPv6/DNS split-path leak | 180 | geo-sensitive backend может видеть другой путь |
| R-011 | account/backend rejection misclassified as transport | 180 | ведёт к бесполезным и рискованным network escalations |
| R-018 | distro/ARM64 runtime gap | 150 | build-only portability не доказывает TUN runtime |
| R-002 | unknown helper bypasses process policy | 144 | agent transport может уйти мимо выбранного egress |
| R-010 | unclean termination leaves stale state | 144 | failure mode переживает процесс |
| R-003 | broad domain fallback captures unrelated Google apps | 140 | нарушает принцип process isolation |
| R-001 | partial startup rollback gap | 128 | сетевые операции пока не transaction-like |

## 6. Risk-driven architecture gates

### Gate A — SAFE MODE production-ready

Должно быть доказано:

- system proxy untouched;
- local listener ownership verified;
- process env sanitization deterministic;
- endpoint diagnostics distinguish transport/backend error.

Связанные риски: R-011, R-022, R-024.

### Gate B — Agent Tunnel production-ready

Должно быть доказано:

- TUN startup/stop transactional;
- stale-state recovery;
- selected PID egress attestation;
- unrelated-process negative egress test;
- IPv4/IPv6/DNS independent verification;
- conflict preflight with common desktop networking stacks;
- privilege separation.

Связанные риски: R-001, R-002, R-003, R-005, R-006, R-010, R-013, R-014, R-015, R-016.

### Gate C — Release-ready

Перед тегом:

```bash
go test ./...
go vet ./...
go run ./cmd/riskcheck -release
```

Ни один незакрытый `RPN >= 150` или `Severity >= 9` риск не должен пройти release gate без `closed` или формального `accepted` с `acceptance_reason`.

## 7. Правила закрытия риска

Риск нельзя закрывать только потому, что код написан.

Минимальные доказательства:

- **unit/contract test** — для локального pure-logic риска;
- **real dependency validation** — для sing-box schema/behavior;
- **privileged runtime integration test** — для TUN/routing/firewall риска;
- **negative test** — для isolation/security инварианта;
- **fault injection** — для rollback/recovery;
- **field evidence** — для платформенно-зависимых O/D оценок.

После mitigation необходимо:

1. добавить evidence;
2. пересчитать O/D и RPN;
3. обновить `last_reviewed`;
4. только затем менять `status` на `closed` или `accepted`.

## 8. Следующий архитектурный порядок работ

Рекомендуемая последовательность минимизирует риск накопления технического долга:

1. **Dual-egress proof** — R-002/R-015.
2. **Health state machine** — R-014, иначе последующие проверки негде агрегировать.
3. **Transactional apply/rollback + stale recovery** — R-001/R-010/R-016.
4. **Privilege helper** — R-006/R-012.
5. **Route conflict preflight** — R-013.
6. **IPv4/IPv6/DNS/UDP assurance** — R-005.
7. **Dynamic process/endpoint learning** — R-002/R-003/R-020.
8. **Backend eligibility boundary** — R-011.
9. **Distro/ARM64 runtime expansion** — R-018.
10. **Release hardening: branch protection, provenance, redaction, atomic persistence** — R-007/R-017/R-019/R-023/R-024.

Эта последовательность сохраняет главный принцип: сначала доказать и наблюдать фактическое поведение системы, затем делать её «умнее».
