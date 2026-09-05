# Архитектурный аудит и Design FMEA — AntigravitiProxi

Базовая оценка: 2026-09-04. Последняя архитектурная синхронизация: 2026-09-05.

`risks/register.json` является машинно-читаемым источником истины по текущим статусам и S/O/D/RPN. `MASTER_PLAN.md` обязан содержать каждый незакрытый Risk ID; связность проверяет `cmd/riskcheck`. Этот документ объясняет причинно-следственную модель и evidence, но не переопределяет реестр.

## 1. Граница системы

```text
Embedded PWA
    │ loopback HTTP/SSE
    ▼
Go control plane
    ├── config/orchestration/health
    ├── Agent Doctor / Antigravity launcher
    └── privileged-operation broker boundary
              │
              ▼
      managed sing-box data plane
      mixed proxy + TUN + DNS + policy
              │
      ┌───────┴────────┐
      ▼                ▼
  vpn-direct       system-direct
  Antigravity      unrelated apps
```

Главные инварианты:

1. **Selected egress:** Antigravity transport, требующий специального маршрута, должен доказуемо идти через выбранный VPN.
2. **Isolation:** unrelated traffic не должен незаметно перейти на `vpn-direct`; broader domain fallback обязан быть видим как `ISOLATION-RELAXED`.
3. **Privilege minimization:** UI/control plane/IDE не должны становиться root/Administrator только ради TUN.
4. **Failure containment:** partial start/crash/reboot не должны приводить к broad cleanup неизвестного network state.
5. **Transport ≠ backend:** доказанный egress не означает account eligibility; server reject не должен запускать бесконечную network escalation.
6. **Evidence before claims:** «конфиг валиден» и «порт открыт» недостаточны для `VERIFIED`.

## 2. Сильные решения, уже подтверждённые evidence

### 2.1 Transport ladder

SAFE MODE остаётся минимально-инвазивным первым уровнем; Agent Tunnel включается явно; authoritative backend/account failure переводится в Agent Doctor/eligibility diagnosis. Это ограничивает blast radius.

### 2.2 Linux routing profile получен из runtime, а не из предположения

Канонический профиль:

```text
auto_route=true
strict_route=true
auto_redirect=false
process/path rules BEFORE sniff
```

Dual-egress netns fixture доказал:

```text
antigravity       -> vpn-direct
language_server   -> vpn-direct
bundled node      -> vpn-direct
ordinary process  -> system-direct
```

`auto_redirect=true` в проверенной topology позволял system default route обойти process policy; поэтому текущий `false` является архитектурным инвариантом до появления нового противоположного runtime evidence. Это снижает R-002/R-015, но оставляет R-013 для сложных desktop route managers.

### 2.3 Supply-chain path для privileged binary fail-closed

Agent Tunnel использует pinned `sing-box 1.14.0`, mandatory official SHA-256, installed binary hash/provenance и real `sing-box check`. Missing/invalid digest больше не warning-only: R-023 закрыт. Upgrade compatibility/SBOM/signing остаются R-007.

### 2.4 Linux privilege boundary уже выделен

Normal path:

```text
control plane (user)
      ↓ explicit start
readiness check
      ↓ if needed
pkexec / PolicyKit
      ↓
fixed-function internal helper
      ├── expected path / non-symlink / owner check
      ├── SHA-256 revalidation
      ├── modprobe/libcap only if needed
      ├── exact setcap allowlist
      └── post-operation SHA-256/cap verification
      ↓
control plane continues as user
```

Приложение не читает/хранит password и helper не принимает arbitrary command. Это materially mitigates R-006 и R-012 на Linux. R-006 не закрыт, потому что Windows minimal UAC helper ещё не реализован; R-012 остаётся mitigating до ordinary-user upgrade/distro fixture.

### 2.5 Lifecycle и recovery имеют ownership evidence

До mutation сохраняется durable baseline. Linux использует reserved table `20229` и rule priorities `19000..19031`; recovery удаляет только доказуемо owned state. SIGKILL fixture дополнительно вносит unrelated route/rule и доказывает, что они переживают recovery. Это основной control для R-001/R-010/R-016/R-025/R-026.

### 2.6 Runtime assurance композиционная

`GET /api/attestation` связывает:

```text
process tree
  → active PID
  → socket/source endpoint
  → sing-box connection/outbound
  → vpn-direct
  → external egress
```

External evidence имеет bounded TTL и lifecycle invalidation. UI отдельно показывает Assurance и Isolation. Это существенно улучшает detection для R-002/R-014/R-015.

### 2.7 Loopback-only теперь hard invariant

Control plane, local proxy и observability normal mode принудительно loopback-only. R-008 закрыт.

## 3. Сохраняющиеся слепые зоны

### 3.1 Full Windows privilege separation отсутствует — R-006

Linux fixed-function helper уже реализован, но Windows normal Tunnel path всё ещё может требовать whole-app Administrator. Целевая Windows boundary должна повторять принцип Linux: ordinary-user UI/control plane + minimal structured UAC helper.

### 3.2 Windows end-to-end egress assurance неполна — R-002/R-015/R-027

Native Windows fixture уже доказывает exact local endpoint → PID. Но ещё не доказана полная цепочка реального Agent Tunnel:

```text
PID → socket → sing-box outbound → controlled external egress
```

Также stale route ownership должен быть привязан к interface LUID/route compartment до автоматического удаления Windows routes.

### 3.3 IPv4/IPv6/DNS/UDP/QUIC не независимы — R-005

IPv4 success не должен скрывать IPv6/DNS/QUIC split path. Нужна family/protocol matrix с отдельным egress evidence.

### 3.4 Domain fallback остаётся шире process policy — R-003

Проблема теперь не скрывается: UI/assurance показывает `ISOLATION-RELAXED`. Конечная mitigation — learned reviewed process+endpoint policy и отрицательные tests unrelated Google client.

### 3.5 VPN interface может пересоздаваться — R-004

Preflight ловит missing/DOWN interface, но не обеспечивает transparent stable-identity rebind после reconnect.

### 3.6 Desktop route conflicts не покрыты матрицей — R-013/R-018

Route-conflict preflight уже существует, но privileged runtime strongest на Ubuntu amd64. Требуются Debian/Fedora, ARM64, NetworkManager/systemd-networkd, Docker/Podman и VM stacks.

### 3.7 Backend/account reject ещё не first-class health dimension — R-011

Agent Doctor существует, но health state machine ещё должна прекращать transport escalation автоматически после authoritative server rejection.

### 3.8 Endpoint/helper topology может дрейфовать — R-002/R-020

Process tree и connection tracker дают discovery substrate, но reviewed dynamic learning ещё не завершён.

### 3.9 Branch protection отсутствует — R-017

CI сильный, но `main` пока не защищён required status checks. Поэтому direct push остаётся governance gap.

### 3.10 Diagnostics/persistence hardening не завершены — R-009/R-019/R-024

Нужны hosts TTL/ownership, centralized redaction, Windows ACL evidence и миграция remaining direct writes.

## 4. Метод FMEA

- **Severity (S)**: 1..10.
- **Occurrence (O)**: 1..10.
- **Detection (D)**: 1..10; 10 = трудно обнаружить до ущерба.
- **RPN = S × O × D**.

Project thresholds:

- `RPN >= 150` — high/action-required;
- `Severity >= 9` — release-significant независимо от RPN.

RPN — инженерная оценка, а не статистическая истина. Снижение O/D допустимо только после concrete evidence.

## 5. Текущая приоритизация

Точные значения всегда брать из `risks/register.json`. На момент синхронизации:

| Risk | Current RPN | Status | Основной остаточный риск |
|---|---:|---|---|
| R-005 | 180 | open | IPv6/DNS/UDP/QUIC split path |
| R-011 | 180 | mitigating | backend reject vs transport |
| R-020 | 168 | open | backend endpoint drift |
| R-013 | 160 | mitigating | Docker/VM/NM route conflict |
| R-018 | 150 | open | distro/ARM64 privileged runtime gap |
| R-003 | 140 | mitigating | broad domain fallback scope |
| R-006 | 128 | mitigating | Windows privilege separation |
| R-004 | 120 | mitigating | VPN interface recreation |
| R-012 | 120 | mitigating | capability-loss upgrade/distro fixture |
| R-027 | 120 | open | Windows exact stale-route ownership |
| R-002 | 108 | mitigating | Windows full helper egress proof |
| R-019 | 108 | mitigating | diagnostic privacy / Windows ACL |
| R-014 | 96 | mitigating | remaining health dimensions/states |
| R-015 | 90 | mitigating | Windows + dual-stack assurance gap |
| R-009 | 84 | open | hosts override TTL/ownership |
| R-001 | 72 | mitigating | every-phase fault injection |
| R-010 | 72 | mitigating | orphan ownership / every-phase crash |
| R-016 | 72 | mitigating | bounded forced-stop recovery matrix |
| R-021 | 72 | mitigating | exhaustive UI/settings/runtime contract |
| R-017 | 64 | open | unprotected main |
| R-007 | 54 | mitigating | upgrade compatibility/release provenance |
| R-025 | 54 | mitigating | broader network-manager recovery matrix |
| R-022 | 32 | mitigating | orphan/foreign-listener ownership token |
| R-026 | 32 | mitigating | old-schema migration/fault injection |
| R-024 | 36 | mitigating | remaining direct persistence |
| R-023 | 10 | closed | digest fail-closed implemented |
| R-008 | 9 | closed | loopback hard invariant implemented |

## 6. Architecture gates

### Gate A — SAFE MODE

Нужно сохранять доказательства:

- global/system proxy untouched;
- managed local listener ownership;
- deterministic process env sanitization;
- backend/transport diagnosis separated.

Связанные риски: R-011, R-022, R-024.

### Gate B — Linux Agent Tunnel production-ready

До полного production claim должны быть закрыты/приняты:

- every-phase transactional fault injection — R-001/R-010/R-016/R-026;
- ordinary-user capability-loss upgrade fixture — R-012;
- distro/ARM64/conflict matrix — R-013/R-018;
- IPv4/IPv6/DNS/UDP/QUIC evidence — R-005;
- learned policy or explicit acceptance of relaxed fallback — R-003;
- redacted diagnostics — R-019.

Linux fixed-function privilege helper сам по себе уже evidence, а не future task.

### Gate C — Windows Agent Tunnel production-ready

Требуется:

- minimal UAC helper; whole-app Administrator не считается конечной архитектурой — R-006;
- full PID/socket/outbound/external-egress runtime proof — R-002/R-015;
- interface LUID/route-compartment stale-state ownership — R-027;
- native Windows ACL proof — R-019/R-024.

### Gate D — Release-ready

Перед tag:

```bash
go test ./...
go vet ./...
go run ./cmd/riskcheck -release
```

Незакрытый `RPN >= 150` или `Severity >= 9` risk должен быть `closed` или формально `accepted` с `acceptance_reason`.

## 7. Правила изменения статуса

Риск нельзя закрывать потому, что «код написан». Нужен соответствующий тип evidence:

- unit/contract test — pure logic/API contract;
- real dependency check — sing-box schema/behavior;
- privileged runtime integration — TUN/routing/privilege;
- negative test — isolation/security;
- fault injection — rollback/recovery;
- native platform fixture — Windows/Linux semantic claims;
- field evidence — O/D для heterogeneous desktop hosts.

После mitigation:

1. добавить evidence;
2. проверить, что evidence соответствует именно failure mode;
3. только затем пересчитать O/D/RPN;
4. обновить `last_reviewed`;
5. затем менять `status`.

## 8. Следующий порядок работ

Приоритет от текущего состояния, а не от старого MVP:

1. **Windows minimal UAC privilege helper** — R-006.
2. **Windows full Agent Tunnel egress chain + route ownership** — R-002/R-015/R-027.
3. **IPv4/IPv6/DNS/UDP/QUIC assurance** — R-005.
4. **Linux ordinary-user upgrade/capability-repair + distro/ARM64 matrix** — R-012/R-018.
5. **Docker/VM/NetworkManager conflict matrix + every-phase fault injection** — R-001/R-010/R-013/R-016/R-025/R-026.
6. **Dynamic helper/endpoint learning and fallback narrowing** — R-002/R-003/R-020.
7. **Backend/account first-class health classification** — R-011/R-014.
8. **Redaction, ACLs, remaining atomic persistence, hosts TTL** — R-009/R-019/R-024.
9. **Protect main + release provenance/SBOM/signing** — R-007/R-017.

Принцип остаётся прежним: сначала доказать фактическое поведение и ownership, затем повышать автоматизацию.
