# Linux — эксплуатация, права и проверка Agent Tunnel

Этот документ описывает Linux-специфичную часть AntigravitiProxi. Цель — запускать UI/control-plane и Antigravity IDE от обычного пользователя, а повышенные права давать только управляемому `sing-box` helper.

## Поддерживаемая схема

```text
user session
├── AntigravitiProxi (обычный пользователь)
├── Antigravity IDE (обычный пользователь)
└── managed sing-box
      ├── CAP_NET_ADMIN
      ├── CAP_NET_RAW
      ├── CAP_SYS_PTRACE
      ├── CAP_DAC_READ_SEARCH
      ├── TUN: antigravity-tun
      ├── auto_route
      ├── strict_route
      └── process_name / process_path policy
```

SAFE MODE не требует TUN и обычно не требует повышенных прав.

Agent Tunnel использует:

- `sing-box` 1.14.0;
- `/dev/net/tun`;
- `auto_route`;
- `strict_route=true` на Linux;
- `auto_redirect=false` в текущем process-isolation профиле;
- process matching для Antigravity/language server/helper процессов;
- `bind_interface` к явно выбранному VPN-интерфейсу;
- `system-direct` для unrelated traffic после захвата TUN.

### Почему сейчас `auto_redirect=false`

Официальная документация sing-box в общем случае рекомендует Linux `auto_redirect` из-за производительности и совместимости с Docker. Но для нашей более узкой задачи обнаружился важный конфликт семантики: в sing-box 1.14 fallback `ip rule`, создаваемый `auto_redirect`, проверяется после системных `main/default` rules. При существующем обычном default route локальный процесс может уйти через него до попадания в TUN, а значит `process_name/process_path` policy вообще не увидит соединение.

Мы воспроизвели это отдельным dual-egress тестом: при `auto_redirect=true` процесс с `/proc/self/comm=antigravity` сохранял системный egress. После перехода на `auto_route + strict_route` без `auto_redirect` тот же runtime-тест доказал:

```text
antigravity         -> vpn-direct    -> vpn0
language_server     -> vpn-direct    -> vpn0
bundled .../node    -> vpn-direct    -> vpn0   (process_path_regex)
ordinary process    -> system-direct -> sys0
```

Поэтому `auto_redirect=false` — не случайная настройка, а зафиксированный архитектурный инвариант текущей Linux реализации. Риск возможных конфликтов с Docker/VM/NetworkManager отдельно отслеживается FMEA как R-013.

## Рекомендуемая установка

Сначала запустите AntigravitiProxi как обычный пользователь и дайте ему установить managed `sing-box`:

```bash
git clone https://github.com/Homiakus/AntigravitiProxi.git
cd AntigravitiProxi
go run ./cmd/antigraviti-proxi
```

По умолчанию managed binary находится примерно здесь:

```text
~/.config/AntigravitiProxi/bin/sing-box
```

Проверьте фактический путь в web UI или:

```bash
find "${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi" -type f -name sing-box -print
```

Для полноценного **process-aware Agent Tunnel** выдайте capabilities только helper-бинарнику:

```bash
BIN="${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box"

sudo setcap cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep "$BIN"

getcap "$BIN"
```

Ожидаемый результат должен содержать все четыре capability:

```text
cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search=ep
```

Назначение:

- `CAP_NET_ADMIN` — TUN, routes/policy routing;
- `CAP_NET_RAW` — сетевые операции, нужные transparent path;
- `CAP_SYS_PTRACE` — process/socket attribution через Linux process finder;
- `CAP_DAC_READ_SEARCH` — чтение необходимой `/proc`/process metadata независимо от обычных DAC ограничений.

Последние две capability нужны не для самого создания TUN, а для главного инварианта Agent Tunnel: `process_name/process_path` должны действительно идентифицировать локальный Antigravity process. Именно поэтому preflight теперь проверяет их отдельно.

После обновления/replacement managed `sing-box` file capabilities могут исчезнуть, поскольку capabilities привязаны к inode файла. В этом случае AntigravitiProxi останавливает Agent Tunnel на preflight и выдаёт точную команду `setcap`. Это известный FMEA риск R-012; автоматическое capability-preserving обновление запланировано.

## Не запускать IDE от root

Предпочтительный режим — AntigravitiProxi и Antigravity работают от обычного desktop-пользователя, а capabilities находятся на `sing-box`.

Если control-plane всё же был запущен через `sudo`/`pkexec`, Linux launcher:

1. определяет исходного пользователя по `SUDO_UID`/`PKEXEC_UID`;
2. использует его home/config для поиска Antigravity settings;
3. перед запуском IDE сбрасывает UID/GID обратно на desktop-пользователя;
4. восстанавливает `HOME`, `USER`, `LOGNAME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`;
5. при наличии `/run/user/<uid>` восстанавливает `XDG_RUNTIME_DIR` и DBus session address.

Если исходного desktop-пользователя безопасно определить нельзя, launcher отказывается запускать Antigravity как root.

## Проверка ядра

```bash
set -e

test -e /dev/net/tun && echo "TUN: OK" || echo "TUN: MISSING"

lsmod | grep -E '(^| )(tun|nf_tables|nfnetlink_queue)( |$)' || true

command -v nft >/dev/null && nft --version || true
command -v ip  >/dev/null && ip -Version || true
```

Если `/dev/net/tun` отсутствует:

```bash
sudo modprobe tun
```

`nf_tables/nfnetlink_queue` больше не являются обязательным условием для текущего Agent Tunnel профиля, потому что `auto_redirect=false`, но они остаются важны для будущих альтернативных routing profiles и для диагностики конфликтов хоста.

## Проверка VPN-интерфейса

Agent Tunnel не стартует с несуществующим или выключенным upstream-интерфейсом.

Посмотреть интерфейсы:

```bash
ip -br link
ip -br addr
ip route
ip -6 route
```

Примеры имён:

```text
wg0
wg-amnezia
amneziawg
amnezia
vpn0
tun0
tailscale0
```

В web UI нужно выбрать именно фактическое имя интерфейса, которое присутствует в `ip link` и находится в состоянии `UP`.

## Проверка SAFE MODE

SAFE MODE не создаёт `antigravity-tun`:

```bash
ip link show antigravity-tun 2>/dev/null && echo "unexpected TUN" || echo "SAFE: no Agent TUN"
```

После запуска SAFE MODE:

```bash
curl -x http://127.0.0.1:7890 -I https://cloudcode-pa.googleapis.com/
```

Любой настоящий HTTP response code подтверждает, что HTTP CONNECT дошёл до backend; `404` на корневом пути допустим и не означает сетевую ошибку.

## Проверка Agent Tunnel

После нажатия **Agent Tunnel + запустить IDE**:

```bash
ip -details link show antigravity-tun
ip addr show dev antigravity-tun
ip rule
ip route show table all | grep -E 'antigravity|172\.31\.255|2022|9000' || true
```

Проверка capabilities:

```bash
BIN="${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box"
getcap "$BIN"
```

Параллельно mixed proxy остаётся доступен для диагностических запросов:

```bash
curl -x http://127.0.0.1:7890 -I https://oauth2.googleapis.com/
curl -x http://127.0.0.1:7890 -I https://cloudcode-pa.googleapis.com/
```

## Проверка cleanup

Нормальная остановка Agent Tunnel должна убрать TUN и созданные route state.

После **Остановить Tunnel**:

```bash
if ip link show antigravity-tun >/dev/null 2>&1; then
  echo "ERROR: antigravity-tun still exists"
  exit 1
else
  echo "cleanup: OK"
fi
```

На Linux managed `sing-box` получает `SIGTERM`, а не немедленный `SIGKILL`, чтобы успеть убрать маршруты. Если Go control-plane аварийно исчезает, дочернему `sing-box` задан `PDEATHSIG=SIGTERM`, поэтому helper не должен оставаться бесхозным. SIGKILL/power-loss всё ещё требуют startup stale-state recovery — FMEA R-010/R-016.

## Что теперь доказывает CI

Linux CI создаёт **две независимые L3 uplink-сети** внутри изолированных network namespaces:

```text
client namespace
├── sys0  10.251.0.2  metric 10   ← обычный default
└── vpn0  10.250.0.2  metric 100  ← выбранный VPN

sink namespace
└── 203.0.113.10:18080
    возвращает source IP клиента
```

Затем запускается настоящий pinned `sing-box 1.14.0` и детерминированные Go probe-бинарники. Проверяется:

1. `antigravity-tun` реально создан;
2. mixed listener жив;
3. бинарник с process name `antigravity` виден серверу как `10.250.0.2`;
4. `language_server` виден как `10.250.0.2`;
5. generic `node`, расположенный внутри пути `.../antigravity-bundle/node`, также виден как `10.250.0.2` — это проверка `process_path_regex`;
6. обычный `agp-egress-probe` виден как `10.251.0.2` — отрицательная проверка isolation;
7. выполняется graceful stop;
8. `antigravity-tun` исчезает.

Таким образом CI доказывает не только «конфиг принят» или «TUN существует», а фактический **dual-egress source-interface invariant**.

Отдельно CI продолжает выполнять:

- `go test ./...`;
- `go vet ./...`;
- `go run ./cmd/riskcheck`;
- real `sing-box check` generated config;
- Linux amd64 build;
- Linux arm64 build.

Runtime TUN/dual-egress сейчас выполняется на Ubuntu GitHub runner amd64. ARM64 компилируется, но privileged TUN runtime на реальном ARM64 runner пока не доказан — FMEA R-018.

## Диагностические команды

```bash
printf '%s\n' '=== OS ==='
uname -a
cat /etc/os-release

printf '%s\n' '=== USER ==='
id
printf 'HOME=%s\n' "$HOME"
printf 'XDG_CONFIG_HOME=%s\n' "${XDG_CONFIG_HOME:-}"
printf 'XDG_RUNTIME_DIR=%s\n' "${XDG_RUNTIME_DIR:-}"

printf '%s\n' '=== TUN ==='
ls -l /dev/net/tun 2>&1 || true
ip -details link show antigravity-tun 2>&1 || true

printf '%s\n' '=== NETWORK ==='
ip -br link
ip -br addr
ip rule
ip route
ip -6 route

printf '%s\n' '=== CAPABILITIES ==='
command -v getcap >/dev/null && \
  getcap "${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box" || true

printf '%s\n' '=== PROCESSES ==='
ps -eo user,pid,ppid,comm,args | grep -E 'Antigravity|antigravity|language_server|agy|sing-box' | grep -v grep || true

printf '%s\n' '=== PORTS ==='
ss -lntup | grep -E ':48765|:7890' || true
```

## Известные границы

- privileged runtime/dual-egress proof сейчас покрывает Ubuntu amd64;
- Linux ARM64 пока build-only;
- Debian/Fedora family, NetworkManager/systemd-networkd и Docker/Podman/VM combinations требуют отдельного runtime matrix — R-013/R-018;
- CI доказывает routing policy синтетических процессов, но production health ещё должен доказать egress **реального обнаруженного PID tree Antigravity** на пользовательском хосте — R-002/R-015;
- IPv6, UDP/QUIC и dual-stack DNS должны проверяться независимо — R-005;
- `auto_redirect=false` усиливает determinism process routing, но потенциально повышает риск конфликтов с сложной host routing topology; поэтому route-conflict preflight является обязательным P1 hardening, а не необязательной оптимизацией.
