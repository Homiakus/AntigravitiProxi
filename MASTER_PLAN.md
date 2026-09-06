# MASTER PLAN — AntigravitiProxi

## Приоритетный пересмотр архитектуры — 2026-09-06

Аудит исходников на базе `e75bd37`. Этот раздел определяет текущую последовательность работ и имеет приоритет над историческим backlog ниже. Задача продукта: постоянно доступный локальный HTTP/SOCKS proxy для Antigravity IDE и Cockpit Tools через выбранный VPN. Работоспособность подтверждается операцией клиента. Создание TUN, namespace, cgroup и получение привилегий не являются частью обычного запуска.

Предыдущие отметки `[x]` ниже описывают историческую реализацию/fixtures, а не проверку текущей объединённой версии. В частности, утверждения о строгом ownership health, доступном из UI Agent Tunnel и завершённом UI сейчас не соответствуют коду. До выполнения A-01 и A-08 считать эти утверждения непроверенными. Старый план production Agent Tunnel сохраняется как отложенный backlog отдельного экспериментального режима.

### Рекомендуемое решение и границы

Сохранить Go control plane и sing-box: переписывание транспорта не устраняет найденные ошибки управления жизненным циклом. На Linux запускать существующее приложение как пользовательскую службу, управляющую одним обычным экземпляром sing-box. UI — клиент службы. Достаточно одного владельца процесса и последовательного выполнения start/stop/config; отдельный микросервис, очередь задач или новая система attestations для этого не нужны.

```text
пользовательская служба AntigravitiProxi
  ├─ локальный API + UI: настройки, start/stop, последние ошибки
  ├─ один sing-box: 127.0.0.1:7890 HTTP CONNECT / SOCKS5
  │    └─ DNS и соединения через выбранный VPN-интерфейс
  └─ интеграции клиентов
       ├─ Antigravity: поддерживаемый proxy способ + проверка операции IDE
       └─ Cockpit: его настройки/launcher + проверка обновления квот
```

Запуск службы восстанавливает сохранённое намерение `enabled`; явный Stop его сбрасывает. Закрытие браузера не влияет на proxy. Завершение самой службы прекращает дочерний процесс; перезапуск службы восстанавливает proxy при `enabled=true`. Не обещать непрерывность существующих TCP-сессий при обновлении службы.

Политика выхода задаётся явно: выбранный VPN обязателен либо пользователь выбрал системный маршрут. При пропадании обязательного VPN запрещён незаметный переход на системный выход. Обычный proxy не гарантирует перехват запросов приложений, игнорирующих proxy, и не является kernel kill-switch. Экспериментальный TUN должен иметь отдельный явный контракт; диагностическая ошибка не должна автоматически его включать.

### Подтверждённые изъяны и задачи

Все задачи ниже TODO; завершение требует указанного результата, а не наличия функции или текста в UI.

### Execution status — 2026-09-06

- **A-01 — implementation slice complete:** health публикует `listener_reachable` отдельно и не поднимает `mixed_listener_owned.ok` через readiness fallback; обычный proxy может быть healthy при неизвестном `/proc` ownership, но ownership остаётся `false`. Нужны публичный lifecycle test и проверка недоступного `/proc` на целевой Linux системе.
- **A-02 — implementation slice complete:** добавлен persisted `proxy_auto_start`, миграция старых конфигураций с включённым значением, auto-start control plane с ограниченным retry и явное отключение при Stop. Live-проверка после перезапуска службы подтверждена; crash/reboot acceptance ещё открыта.
- **A-04 — in progress:** start/stop/close/config операции сериализованы общей lifecycle lock. Нужны concurrent acceptance tests и rollback предыдущей рабочей конфигурации.
- **A-06 — implementation slice complete:** удалена недостижимая старая TUN-ветка `renderSetup` и связанный UI-код подготовки маршрута; обычный экран явно описывает loopback proxy без TUN и системных proxy-настроек. Полный пересмотр оставшихся legacy-подсказок и adapters ещё открыт.
- **A-11 — implementation slice complete:** `sing-box version` кэшируется на 30 секунд, а UI не допускает перекрывающиеся status/attestation polling-запросы. Диагностика DNS по-прежнему запускается только при открытии/ручном обновлении.
- **A-05 — integration slice complete:** штатный launcher не находил Snap Antigravity; Cockpit дополнительно содержал ошибочный `antigravity_app_path` на `language_server_linux_x64`, из-за чего child становился `defunct`. Исправлены Snap discovery в control plane и Cockpit runtime-конфигурация: app path указывает на wrapper `snap run antigravity-ide-snap.antigravity-ide`, `--no-sandbox` включён. После перезапуска Cockpit root IDE и language servers живы, Cloud Code `loadCodeAssist`/`fetchAvailableModels` запросы уходят через proxy. Осталась проверка реального agent execution в UI и persistence внешней Cockpit-конфигурации при обновлении приложения.
- **A-05 — runtime evidence:** установлен Snap `antigravity-ide-snap 2.5.5` (revision 5, latest/stable), внутренний Electron/IDE — `1.107.0`. Свежий language-server log показывает `RESOURCE_EXHAUSTED (code 429)` → `agent executor error: model unreachable`; это backend quota/overload, а не transport failure. `proxy_running=true`, `health.state=healthy`, language servers живы. Отдельно остаются некритичные `Playwright driver 404`, invalid `/usr/bin/cs` и остановка `autoloop-code` MCP.
- **A-05 — model/version audit:** официальный download page по-прежнему публикует standalone IDE `2.5.5`, но актуальная платформа Antigravity 2.12.2 уже документирует Gemini 3.8 и исправления cold-start `HTTP 429`. Локальный backend catalog для текущей авторизации содержит `gemini-3.6-flash-*`, `gemini-pro-agent`, Claude/GPT-OSS, но не `gemini-3.8`; это нельзя исправлять ручным редактированием cache — видимость модели задаётся сервером/аккаунтом. Следующий отдельный шаг: проверить официальный Linux build/канал и повторную авторизацию после обновления, затем отличить отсутствие модели в UI от account rollout.
- **A-08 — first slice complete:** актуальный UI contract test и полный `go test ./...` проходят; documentation consistency также проходит. Полная API negative matrix ещё не добавлена.

Verified on this revision: `go test ./...`, `go vet ./internal/app ./internal/proxy ./internal/webui ./internal/consistency`, `git diff --check`; live API/listener/HTTPS proxy check passed after restart with auto-start enabled. Runtime service/reboot acceptance is still open.

| ID / приоритет | Дефект и свидетельство в коде | Исправление и критерий готовности |
|---|---|---|
| A-01 / P0 | `proxy/health.go` заменяет `owned=false` на `true` после `proxyReadinessFallback`; `app.startSafeProxy` принимает любой доступный порт. Чужой listener может быть объявлен своим. Ранее внесённый обход маскирует причину сбоя. [R-014, R-022] | Разделить process alive, listener reachable, ownership (yes/no/unknown), proxy handshake и upstream. Не писать `mixed_listener_owned.ok=true` при неизвестном владельце. Проверить обычный дочерний процесс, недоступный `/proc`, занятый чужим процессом порт и выход процесса во время старта. Проверка должна проходить через публичный start workflow, включая fallback. |
| A-02 / P0 | `app.Serve` поднимает только HTTP API; `Close` останавливает sing-box; в `manager.startLocked` выход ребёнка лишь записывается в лог. Автозапуска и восстановления нет. [R-010, R-016] | Пользовательская служба, сохранённое enabled, ограниченные повторные старты с задержкой и лимитом; явный Stop не перезапускается. Проверить вход в desktop, перезапуск службы, crash sing-box, занятый порт и закрытие UI. Windows adapter запланировать отдельно после Linux acceptance. |
| A-03 / P0 | `handleTunnelStart/Launch` молча подменяют TUN обычным proxy; `/tunnel/stop` останавливает общий процесс; status продолжает сообщать поддержку tunnel. Это изменение контракта, а не полноценная совместимость. [R-001, R-021] | Обычные start/launch используют один общий путь. Старые tunnel API возвращают явный ответ о недоступности/миграции, без запуска приложения под другим обещанием изоляции. Проверить старый клиент: вызов tunnel не выключает рабочий proxy. Сохранить отдельное восстановление ранее созданного TUN. |
| A-04 / P0 | `startSafeProxy` делает Health → Stop → Start без блокировки всей операции; handlers config/stop/start могут пересекаться. При деградации даже живой proxy сначала останавливается; отмена HTTP-запроса запускает rollback общего Manager. [R-001, R-014, R-021] | Одна блокировка жизненного цикла и идентификатор поколения запуска; отмена/rollback относятся только к своему поколению. Повторный Start идемпотентен. Настройки валидируются до остановки; неуспешная замена восстанавливает предыдущую рабочую конфигурацию. Проверить concurrent start/start, start/stop, config/start и отключение браузера. |
| A-05 / P0 | В `antigravity/antigravity.go` launcher только создаёт процесс с env; Cockpit integration отсутствует. У уже работающего single-instance приложения env может не измениться. `ForceProductionEndpoint` применяется без диагностики необходимости. [R-011, R-020, R-021] | Раздельные adapters Antigravity/Cockpit с обнаружением executable и уже работающего экземпляра. Учитывать реальные proxy-настройки каждого клиента; не считать env доказательством охвата WebView/helpers. Pin endpoint вынести в отдельное восстановительное действие. Acceptance: Cockpit обновляет квоты; IDE выполняет реальный запрос агента; отказ backend сохраняется как backend error. |
| A-06 / P1 | `renderSetup` возвращает управление до старого кода, но `renderPolicy` всё ещё рисует strict/relaxed; HTML содержит рекомендации TUN, status по умолчанию `userspace-soft`. UI пишет «VPN не нужен», хотя `writeConfig` привязывает DNS и outbound к выбранному интерфейсу. [R-003, R-014, R-021] | Один экран: proxy, выбранный выход, IDE/Cockpit, проверка соединения, последняя ошибка. Удалить недостижимую ветку setup и ложные обещания изоляции. Видимое состояние берётся из фактического режима и проверки, а не сохранённого fallback флага. |
| A-07 / P1 | `diagnostics.lookupIP/dohType` сводят timeout, HTTP failure, NXDOMAIN и пустой ответ к nil. Новый suspicious считает отсутствие ответа подозрительным, но два отказавших источника дают false. `Collect` последовательно выполняет 24 DNS lookup для четырёх доменов. [R-005, R-011, R-014] | Результат каждого resolver: status, addresses, error, duration, source. Разные IP — нейтральное наблюдение; недоступность resolver — unknown/unavailable, не доказательство подмены. Ограниченная параллельность, общий deadline, переиспользование HTTP transport. Проверить различные валидные A/AAAA, timeout, NXDOMAIN, NODATA и отказ обоих источников. |
| A-08 / P0 | Проверка `go test ./internal/webui ./internal/consistency` в ходе аудита: webui FAIL из-за отсутствующего текста «Подготовить и запустить Antigravity», consistency PASS. Проверки строк позволяют документации и реализации противоречить друг другу. Ранее `-run '^$'` не запускал тесты. [R-017, R-021] | Восстановить актуальные acceptance tests действий UI/API и проверки отрицательных сценариев; синхронизировать README/architecture/FMEA. Полный обычный test suite, race и vet должны пройти на объединённом исходнике. Не объявлять production по компиляции или наличию маркеров. |
| A-09 / P1 | `Health` читает journal для обычного proxy; `startSafeProxy` из-за journal может перезапустить доступный транспорт. `networkAttestation` возвращает idle для proxy, но UI опрашивает его каждые 5 секунд. [R-014, R-025, R-026] | Вынести состояние legacy recovery отдельно от transport health. Проверять влияние оставшихся маршрутов до признания выхода исправным; сохранить безопасную owned-only очистку. Неприменимые tunnel attestations не опрашивать. Не удалять журнал ради зелёного статуса. |
| A-10 / P1 | `manager.writeConfig` привязывает DNS/outbound к имени интерфейса, а proxy health не проверяет VPN. Исчезновение/пересоздание amn0 может оставить зелёный порт при неработающем выходе. [R-004, R-005] | Отдельно отражать VPN availability и свежую проверку выхода; проверять смену interface index, down/up и восстановление. Ошибка upstream не убивает исправный локальный listener. Смена выхода выполняется явно, с проверяемой политикой отсутствия fallback. |
| A-11 / P1 | `status` выполняет version subprocess и kernel checks при каждом запросе; `Health` делает TCP connect, UI повторяет polling независимо от завершения предыдущего. Фоновая диагностика создаёт нагрузку и шум соединений. [R-014] | Кэшировать неизменяемую версию, пропускать неактивные подсистемы, запретить наложение polling. Read-only status не должен запускать install/recovery или менять транспорт; частичные ошибки показывать рядом с конкретной проверкой. |
| A-12 / P1 | В Git включён ELF `antigraviti-proxi`; документация после merge частично заменена remote-версией. Бинарник был построен до итогового merge, поэтому соответствие исходникам не подтверждено. [R-007, R-017] | Сборки публиковать CI artifacts/releases с revision/version/hash; убрать бинарник из отслеживания при следующем implementation commit, локальную рабочую копию сохранить. Проверять исходники итогового merge; DONE в плане привязать к revision и результату проверки. |

### Что ещё требуется доказать

- Причина недоступности `/proc/<pid>/fd` не установлена. Проверить права, file capabilities установленного sing-box и namespace процесса. `processSocketInodes` сейчас подавляет ошибки Readlink. Не выдавать control plane дополнительные права ради зелёного индикатора. Для обычного режима предпочтителен отдельный непривилегированный binary; необходимость bind-interface privileges проверить на целевой ОС. **[A-01, R-006, R-012]**
- `Pdeathsig` требует отдельной проверки в Go/Linux lifecycle; считать его причиной конкретных остановок по имеющимся логам нельзя. **[A-02, R-010]**
- По журналу предыдущей сессии Cockpit завершил обновление пяти аккаунтов без ошибок и получал HTTP 200 на quota API. Это доказывает конкретную операцию в то время, но не все функции Cockpit и не работу агента IDE. Источник браузерного `NetworkError` ещё не локализован по URL/action/time. **[A-05]**
- Открытый порт, HTTP CONNECT 200, валидный TLS, ответ backend и успешная операция клиента — разные результаты. HTTP 404 на `/` Google endpoint подтверждает доступность HTTP, но не API-операцию. **[A-01, A-05]**

### Порядок реализации и приёмка

1. **A-01 + A-08:** воспроизводимый baseline и честный статус. Сначала регрессия реального failed start, затем исправление. Не отключать проверку чужого listener.
2. **A-03 + A-04:** согласованный API и последовательный lifecycle. Действия устаревшего UI и два одновременных клиента не должны разрушать работающий транспорт.
3. **A-02 + A-10:** служба и стабильный выход через VPN. Проверить восстановление после crash и VPN down/up; явный Stop остаётся остановкой.
4. **A-05 + A-06:** полноценные IDE/Cockpit adapters и простой UI. Проверить обе прикладные операции, включая уже открытые приложения.
5. **A-07 + A-09 + A-11 + A-12:** быстрая диагностическая модель, изоляция legacy recovery и воспроизводимая поставка.

Минимальная приёмка: 30 минут одновременного использования IDE и периодического обновления Cockpit, закрытие/открытие UI, перезапуск службы, crash sing-box, разрыв VPN, занятый 7890 и повторный Start. Для каждого случая записать ожидаемый результат, реальный результат и revision. Успех транспорта и отказ аккаунта учитывать отдельно. Миграция не должна удалять чужие маршруты, hosts или данные аккаунтов.

Отложить Windows privileged helper, learned domains, PID egress graphs, kernel-hard namespaces, cgroups и новые isolation dashboards до завершения этого пути. Loopback-only, CSRF, проверку загруженного binary, TLS verification, редактирование секретов и owned-only recovery сохранить: они решают реальные риски и не являются причиной ненужной сложности сами по себе.

### Проверки этого аудита

- `go test ./internal/webui ./internal/consistency`: webui FAIL, consistency PASS; подробность указана в A-08.
- `go vet ./internal/app ./internal/proxy`: PASS.
- `go run ./cmd/riskcheck`: validation PASS; запуск без `-release`, выпуск этим не проверен.
- Полный test suite, race, live VPN failure и прикладные сценарии в этом аудите не запускались. Изменяется только основной план; исправления из таблицы ещё не реализованы.

## 0. Правила планирования и FMEA

Риски являются частью реализации. Источник истины — [`risks/register.json`](risks/register.json), методика — [`docs/ARCHITECTURE_FMEA.md`](docs/ARCHITECTURE_FMEA.md).

Обязательные правила:

- каждый незакрытый риск имеет `owner`, S/O/D, RPN, mitigation, verification и `target_milestone`;
- каждый незакрытый Risk ID обязан присутствовать в этом плане; `go run ./cmd/riskcheck` проверяет связность;
- `RPN >= 150` или `Severity >= 9` — release-significant;
- release tag обязан пройти `go run ./cmd/riskcheck -release`;
- high/critical риск перед release должен быть `closed` либо `accepted` с `acceptance_reason`;
- FMEA пересматривается после изменения TUN/routing/privilege model, инцидента и перед release;
- RPN снижается только после появления проверяемого control/evidence.

### Risk → plan index

| Risk | Основное действие |
|---|---|
| R-001 | P1 transactional startup/rollback + fault injection |
| R-002 | P1/P2 PID egress assurance + helper learning |
| R-003 | P1 visible isolation-relaxed; P2 learned policy |
| R-004 | P2 VPN lifecycle/rebind recovery |
| R-005 | P2/P4 IPv4/IPv6 + DNS + UDP/QUIC assurance |
| R-006 | P1 Linux fixed-function helper done; Windows minimal UAC helper |
| R-007 | P1 compatibility contract; P4 SBOM/provenance/signing |
| R-008 | Closed: enforced loopback-only invariant |
| R-009 | P1 hosts ownership + TTL |
| R-010 | P1 crash/orphan recovery + ownership token |
| R-011 | P2 backend/account-vs-transport classification |
| R-012 | P1 automatic Linux capability repair + upgrade fixture |
| R-013 | P1 route-conflict preflight; P4 Docker/VM/distro matrix |
| R-014 | P1 multidimensional health + explicit lifecycle states |
| R-015 | P1 runtime PID/socket/outbound/external-egress assurance |
| R-016 | P1 bounded shutdown + journal recovery |
| R-017 | P1 protect `main` with required checks |
| R-018 | P4 Linux ARM64 + distro runtime coverage |
| R-019 | P1 diagnostic redaction + Windows ACL evidence |
| R-020 | P2 dynamic backend endpoint discovery |
| R-021 | P1 UI/settings/runtime contract tests |
| R-022 | P1 managed listener/orphan ownership proof |
| R-023 | Closed: fail-closed privileged dependency digest |
| R-024 | P1 migrate remaining persistence writes to atomic helper |
| R-025 | P1 conservative route/rule recovery ownership |
| R-026 | P1 journal corruption/schema migration |
| R-027 | P1 Windows exact route ownership/recovery |

## 1. Каноническая архитектура, которую нельзя рассинхронизировать

### Transport ladder

```text
SAFE MODE
  process-only proxy env
        ↓
local mixed proxy
        ↓
selected VPN

AGENT TUNNEL
  Antigravity process/path
        ↓
  antigravity-tun
        ↓
  vpn-direct → selected VPN

unrelated traffic
        ↓
  system-direct

ELIGIBILITY DIAGNOSIS
  verified transport + authoritative backend reject
        ↓
  Agent Doctor / account-backend diagnosis
```

### Linux routing invariant

```text
auto_route=true
strict_route=true
auto_redirect=false
process/path rules BEFORE sniff
```

Этот профиль зафиксирован реальным dual-egress evidence. Возврат `auto_redirect=true` без нового runtime proof запрещён.

### Linux privilege invariant

```text
ordinary-user control plane
        ↓
explicit Agent Tunnel start
        ↓
TUN/capability readiness
        ↓ if missing
one fixed-function PolicyKit helper
        ↓
verify path/owner/SHA-256
        ↓
modprobe/libcap/setcap exact capabilities
        ↓
re-verify SHA-256 + capabilities
        ↓
ordinary-user control plane continues
```

Пароль не проходит через AntigravitiProxi. Helper не принимает arbitrary command.

### Assurance invariant

`ACTIVE` не равно `VERIFIED`.

```text
process tree → PID → socket/source endpoint → sing-box connection/outbound → external egress
```

Isolation выводится отдельно от route assurance. Domain fallback обязан давать `ISOLATION-RELAXED`.

## 2. Проверенное evidence

- [x] Linux dual-egress runtime: `antigravity`, `language_server`, bundled `node` → `vpn-direct`; ordinary process → `system-direct`. **[R-002, R-003, R-015]**
- [x] Linux capture profile исправлен по runtime evidence: `auto_route + strict_route`, `auto_redirect=false`. **[R-013, R-015]**
- [x] Process/path rules выполняются до sniff. **[R-002]**
- [x] Agent Tunnel success gated TUN + managed-listener ownership; failed readiness triggers rollback. **[R-001, R-014, R-022]**
- [x] Health не принимает «порт открыт» как ownership evidence. **[R-014, R-022]**
- [x] Linux listener ownership: `/proc/<pid>/fd` socket inode ↔ `/proc/net/tcp{,6}`. **[R-022]**
- [x] Windows native endpoint → `netstat -ano` → PID fixture. **[R-002, R-015]**
- [x] Privileged Agent Tunnel install fail-closed по official SHA-256; installed hash + provenance + tamper detection. **[R-007, R-023]**
- [x] Loopback-only persisted control-plane/proxy invariant. **[R-008]**
- [x] Atomic Settings, Agent Tunnel config, provenance и network journal. **[R-024, R-026]**
- [x] Durable Linux pre-change route/rule/DNS/firewall fingerprint. **[R-001, R-010, R-013, R-016]**
- [x] Reserved Linux route table `20229` + rule priorities `19000..19031`; collision preflight до mutation. **[R-013, R-025]**
- [x] SIGKILL recovery fixture сохраняет unrelated concurrent route/rule state. **[R-010, R-016, R-025]**
- [x] Corrupt journal → validated `previous-good` or fail-closed; broad cleanup запрещён. **[R-026]**
- [x] Authenticated sing-box runtime API exposes source/process/outbound/destination evidence. **[R-002, R-015, R-019]**
- [x] Linux PID → socket inode → sing-box source endpoint → `vpn-direct` → external VPN source proof. **[R-002, R-015]**
- [x] `GET /api/attestation` + Web UI assurance with bounded egress evidence TTL and lifecycle invalidation. **[R-014, R-015, R-019]**
- [x] Domain fallback visibly reported as `ISOLATION-RELAXED`. **[R-003]**
- [x] Linux ordinary-user one-shot privilege bootstrap through fixed-function PolicyKit helper. **[R-006, R-012]**
- [x] Helper revalidates managed path, symlink/owner boundary and SHA-256 around privileged `setcap`. **[R-006, R-007, R-012]**
- [x] Linux capability loss after managed binary replacement is detected and repaired on next explicit Agent Tunnel start. **[R-012]**
- [x] Race detector is part of CI. **[R-014, R-021]**

## 3. P0 — базовый продукт — завершён

- [x] Go monorepo, Windows/Linux builds.
- [x] Embedded responsive PWA + SSE.
- [x] SAFE MODE.
- [x] Agent Tunnel MVP.
- [x] Agent Doctor CLI/API.
- [x] DoH, VPN interface binding, SOCKS5h/HTTP diagnostics.
- [x] Production Cloud Code endpoint pinning.
- [x] Process-only Antigravity launcher.
- [x] Emergency hosts fallback/rollback.
- [x] FMEA register + `riskcheck`.
- [x] CI build/test/release workflows.

## 4. P1 — production hardening

### 4.1 Privilege/lifecycle

- [x] Linux fixed-function one-shot PolicyKit helper; terminal sudo fallback only when attached; UI/control plane/IDE stay ordinary user. **[R-006, R-012]**
- [x] Linux TUN + exact four-capability readiness and automatic repair. **[R-006, R-012]**
- [x] Linux selected VPN exists + UP before mutation. **[R-004]**
- [x] Root/netns runtime path does not mutate file capabilities unnecessarily. **[R-006]**
- [ ] Implement **Windows minimal UAC helper** so whole control plane need not run Administrator. Helper API must be fixed-function/structured, not shell passthrough. **[R-006]**
- [ ] Windows privilege preflight + one-click helper authorization from UI. **[R-006]**
- [x] Graceful Linux SIGTERM before forced kill + `PDEATHSIG=SIGTERM`. **[R-010, R-016]**
- [x] App shutdown waits for managed helper cleanup. **[R-016]**
- [x] Linux elevated-launch guard restores invoking desktop user and never launches IDE as root when identity cannot be proven. **[R-006]**
- [x] Startup transaction: prepare journal → start → readiness → active evidence; failure rollback. **[R-001, R-014, R-022]**
- [ ] Add fault injection at every journal phase: `prepared`, partial mutation, `active`, `recovering`. **[R-001, R-010, R-016, R-026]**
- [ ] Add externally orphaned helper ownership token/fingerprint before any kill/reclaim action. **[R-010, R-022]**
- [ ] Windows exact interface LUID/route-compartment ownership and stale-route cleanup. **[R-027]**
- [ ] Add ordinary-user upgrade fixture: replace managed sing-box, prove lost xattrs are detected/repaired through PolicyKit, then Tunnel starts without whole-app elevation. **[R-012]**

### 4.2 Process isolation and egress assurance

- [x] Live Antigravity process tree with unknown descendants surfaced. **[R-002]**
- [x] Linux exact PID/socket/outbound/external egress proof. **[R-002, R-015]**
- [x] Windows exact live local endpoint → PID attribution. **[R-002, R-015]**
- [ ] Full Windows Agent Tunnel PID/socket → sing-box outbound → controlled external egress proof. **[R-002, R-015]**
- [x] Route conflict preflight for reserved namespace, custom rules, concurrent VPN and Docker/VM-like interfaces. **[R-013, R-025]**
- [ ] Expand real conflict matrix across NetworkManager/systemd-networkd, Docker/Podman/libvirt/VirtualBox/VMware. **[R-013, R-025]**
- [x] Broad domain fallback visibly marks `isolation-relaxed`. **[R-003]**
- [ ] Add negative runtime fixture: unrelated Google client remains `system-direct` in strict mode and intentionally demonstrates relaxed scope only when fallback enabled. **[R-003]**

### 4.3 Health/orchestration contracts

- [x] Evidence health dimensions: managed process, owned listener, TUN, VPN, network journal. **[R-014, R-022, R-026]**
- [x] Composed assurance: process tree + route + PID/socket + external egress. **[R-002, R-014, R-015]**
- [x] Assurance cache TTL/invalidation on data-plane boundaries. **[R-014, R-015]**
- [ ] Explicit transient operation states with timestamps: `installing → starting → stopping → recovering`. **[R-001, R-014]**
- [ ] Operation IDs + cancellation for long web actions. **[R-001, R-014]**
- [x] One typed/validated tunnel options path; Linux `strict_route=true` normalized as invariant. **[R-021]**
- [ ] Exhaustive API/UI → Settings → generated config contract test for every exposed option. **[R-021]**
- [ ] Independent health dimensions `route`, `dns_v4`, `dns_v6`, `egress`, `agent_process`, `backend`. **[R-005, R-011, R-014, R-015]**

### 4.4 Persistence/security/release engineering

- [x] Atomic Settings/Agent Tunnel/provenance/journal persistence. **[R-024]**
- [ ] Migrate remaining SAFE config / Antigravity settings / hosts metadata where semantically appropriate; add interruption injection. **[R-024]**
- [ ] Hosts ownership metadata + creation time/TTL + startup stale warning/auto-removal. **[R-009]**
- [ ] Central diagnostic redaction for bearer/OAuth, cookies, email-like identifiers, user paths and optional IP anonymization. **[R-019]**
- [ ] Windows DACL/security descriptor proof for API secret and sensitive runtime files. **[R-019, R-024]**
- [x] Missing/invalid official SHA-256 blocks privileged install. **[R-023]**
- [ ] General sing-box compatibility contract before version upgrades. **[R-007]**
- [ ] Explicit old network-journal schema migration matrix. **[R-026]**
- [ ] Protect `main` with required CI checks/ruleset. **[R-017]**
- [ ] Windows MSI/MSIX and Linux `.deb`/desktop entry.
- [ ] Code signing. **[R-007]**

## 5. P2 — routing intelligence

- [ ] Route-probe matrix per VPN candidate. **[R-004, R-015]**
- [ ] Stable VPN identity + automatic rebind after interface recreation. **[R-004]**
- [ ] Auto-select fastest healthy egress only after policy/eligibility checks.
- [ ] Per-endpoint policy: OAuth / Cloud Code / model generation / site.
- [ ] Dynamically learn backend hostname from process command line, SNI and logs with review before persistence. **[R-020]**
- [ ] Dynamically learn helper PID/path topology and reconcile with allowlist. **[R-002, R-020]**
- [ ] Replace broad `*.googleapis.com` fallback with reviewed learned process+endpoint policy. **[R-003]**
- [ ] DoH failover with independent health.
- [ ] IPv4/IPv6 independent egress + DNS assurance; add UDP/QUIC. **[R-005]**
- [ ] Backend/account vs transport classifier; authoritative server reject stops transport escalation. **[R-011]**
- [ ] A/B workflow: same account/different egress and same egress/different account. **[R-011]**

## 6. P3 — UX/UI

- [x] Progressive main UI separates SAFE MODE and Agent Tunnel.
- [x] One-action Linux setup card: sing-box / VPN / privileges / runtime readiness.
- [x] Runtime assurance panel: Assurance / Isolation / PID route / External egress / Evidence age.
- [x] Clear PolicyKit explanation; password is handled by OS, not app. **[R-006]**
- [x] `ISOLATION-RELAXED` is visible when domain fallback broadens policy. **[R-003]**
- [ ] Full first-run wizard with recommended mode derived from evidence.
- [ ] Connection topology visualization with expected vs actual egress.
- [ ] Explicit guided ladder `SAFE MODE → AGENT TUNNEL → ELIGIBILITY DIAGNOSIS`.
- [ ] Advanced view: process tree, unknown helpers, per-connection ownership, route/journal details.
- [ ] One-click redacted diagnostic bundle. **[R-019]**
- [ ] PWA degradation notifications.
- [ ] Offline help.
- [ ] RU/EN localization.
- [ ] Risk dashboard generated from `risks/register.json`.

## 7. P4 — verification matrix

- [x] `go test ./...` + `go vet ./...`.
- [x] Race detector CI.
- [x] Linux real TUN lifecycle runtime.
- [x] Linux dual-egress process/path isolation runtime. **[R-002, R-003, R-015]**
- [x] Deterministic external egress observer fixture. **[R-015]**
- [x] Linux PID/socket route-attestation runtime. **[R-002, R-015]**
- [x] Linux crash recovery preserving unrelated route/rule state. **[R-010, R-016, R-025]**
- [x] Corrupt/previous-good journal fixtures. **[R-026]**
- [x] Native Windows endpoint → PID fixture. **[R-002, R-015]**
- [x] Provenance tamper/missing-digest tests. **[R-023]**
- [ ] Full Windows Agent Tunnel egress fixture. **[R-002, R-015]**
- [ ] Windows forced-kill route ownership fixture. **[R-027]**
- [ ] Linux ARM64 privileged runner. **[R-018]**
- [ ] Debian/Fedora-family privileged runtime matrix. **[R-013, R-018]**
- [ ] Docker/Podman/VM conflict fixtures. **[R-013]**
- [ ] Dual-stack A/AAAA + TCP/UDP/QUIC matrix. **[R-005]**
- [ ] Foreign-listener collision test. **[R-022]**
- [ ] Every journal-phase fault injection. **[R-001, R-010, R-016, R-026]**
- [ ] Windows security descriptor fixture. **[R-019, R-024]**
- [ ] Agent Doctor classification corpus. **[R-011]**
- [ ] Diagnostic secret/redaction corpus + fuzzing. **[R-019]**
- [ ] `staticcheck` + `govulncheck`.
- [ ] SBOM + signed provenance/attestations for release artifacts. **[R-007]**

## 8. Definition of done для production Agent Tunnel

Production-ready утверждение допускается только если одновременно:

1. Linux ordinary-user flow не требует ручного `setcap` в normal path; automatic helper подтверждён upgrade fixture. **[R-006, R-012]**
2. Windows control plane не требует whole-app Administrator для normal Tunnel flow. **[R-006]**
3. Linux и Windows имеют полный PID/socket/outbound/external-egress proof. **[R-002, R-015]**
4. Crash/reboot recovery удаляет только owned network state. **[R-001, R-010, R-016, R-025, R-027]**
5. IPv4/IPv6/DNS/UDP/QUIC paths проверяются отдельно. **[R-005]**
6. Domain fallback либо заменён learned policy, либо явно принят как relaxed mode. **[R-003]**
7. Sensitive diagnostics проходят centralized redaction; Windows ACLs доказаны native evidence. **[R-019, R-024]**
8. `main` защищён required status checks. **[R-017]**
9. Release gate по FMEA проходит без неразрешённых release-significant risks.
