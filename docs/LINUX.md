# Linux — эксплуатация, права и проверка Agent Tunnel

Этот документ описывает Linux-специфичную ветку AntigravitiProxi. Нормальная модель: UI/control plane и Antigravity IDE работают от обычного desktop user, а необходимые TUN/process-inspection privileges получает только hash-verified managed `sing-box` через bounded OS authorization flow.

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
      ├── auto_route=true
      ├── strict_route=true
      ├── auto_redirect=false
      └── process_name / process_path policy
```

SAFE MODE не требует TUN и обычно не требует повышения прав.

Agent Tunnel использует:

- pinned `sing-box 1.14.0`;
- `/dev/net/tun`;
- `auto_route=true`;
- `strict_route=true`;
- `auto_redirect=false`;
- process matching для Antigravity/language server/helper процессов;
- `bind_interface` к явно выбранному VPN-интерфейсу;
- `vpn-direct` для Antigravity path;
- `system-direct` для unrelated traffic.

## Почему `auto_redirect=false`

Для нашей process-aware topology runtime evidence важнее generic recommendation. В dual-egress fixture `auto_redirect=true` позволял существующему системному default route решить путь локального процесса до попадания в TUN policy. После перехода на `auto_route + strict_route` без `auto_redirect` тот же тест доказал:

```text
antigravity         -> vpn-direct    -> vpn0
language_server     -> vpn-direct    -> vpn0
bundled .../node    -> vpn-direct    -> vpn0   (process_path_regex)
ordinary process    -> system-direct -> sys0
```

Поэтому `auto_redirect=false` — архитектурный инвариант текущего Linux профиля. Возможные конфликты со сложной Docker/VM/NetworkManager topology отдельно отслеживаются как R-013.

## Рекомендуемая установка

Запускайте приложение **обычным пользователем**:

```bash
git clone https://github.com/Homiakus/AntigravitiProxi.git
cd AntigravitiProxi
go run ./cmd/antigraviti-proxi
```

Managed binary обычно находится здесь:

```text
~/.config/AntigravitiProxi/bin/sing-box
```

Дальше штатный сценарий выполняется из UI:

1. подключите VPN;
2. выберите VPN interface; если подходящий кандидат ровно один, UI может выбрать его автоматически;
3. нажмите **«Подготовить Tunnel и запустить IDE»**;
4. если Linux host ещё не готов, появится один системный PolicyKit authentication dialog;
5. после подтверждения AntigravitiProxi автоматически подготовит TUN/capabilities, запустит tunnel и проверит runtime readiness.

Вручную выполнять `modprobe`/`setcap` перед штатным запуском больше не требуется.

## Что делает автоматический privilege bootstrap

Обычный user process сначала проверяет `/dev/net/tun` и текущие file capabilities. Если всё готово, повышение прав не происходит.

Если подготовка нужна:

```text
AntigravitiProxi (user)
    ↓
pkexec / PolicyKit
    ↓
то же AntigravitiProxi executable
    ↓
__linux-privileged-setup (fixed-function mode)
    ├── verify expected managed path
    ├── reject symlink / unexpected ownership
    ├── verify expected SHA-256
    ├── modprobe tun, only if needed
    ├── install libcap tooling, only if needed
    ├── setcap exact capability set
    ├── verify SHA-256 again
    └── verify capabilities
    ↓
return to ordinary user process
```

Helper не принимает произвольную команду. Пароль приложение не читает, не хранит и не пишет в stdin. На desktop предпочтителен PolicyKit. Если PolicyKit недоступен, но программа запущена из интерактивного терминала, предусмотрен `sudo` fallback в этом терминале.

Выдаётся ровно:

```text
cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep
```

Назначение:

- `CAP_NET_ADMIN` — TUN и policy routing;
- `CAP_NET_RAW` — операции transparent data plane;
- `CAP_SYS_PTRACE` — process/socket attribution;
- `CAP_DAC_READ_SEARCH` — чтение требуемой `/proc` metadata для точного ownership proof.

## Обновление managed sing-box и R-012

File capabilities привязаны к inode, поэтому replacement binary может их потерять. Теперь это не требует заранее вручную чинить `setcap`: при следующем явном старте Agent Tunnel ordinary-user readiness check обнаруживает потерю capabilities и вызывает тот же fixed-function PolicyKit helper, который повторно проверяет binary и восстанавливает точный capability set.

R-012 остаётся в состоянии `mitigating`, пока не завершена отдельная upgrade fixture, доказывающая этот сценарий на реальном ordinary-user desktop authorization path для всех поддерживаемых distro.

## Ручной fallback

Используйте только если PolicyKit недоступен/отказан и нужно вручную восстановить host:

```bash
BIN="${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box"

sudo modprobe tun
sudo setcap cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep "$BIN"
getcap "$BIN"
```

Ожидаемый capability set должен содержать все четыре capability. Это troubleshooting path, а не нормальная установка.

## Не запускать IDE от root

Предпочтительный режим — AntigravitiProxi и Antigravity работают от desktop user.

Если control plane всё же был запущен через `sudo`/`pkexec`, Linux launcher:

1. определяет исходного пользователя по `SUDO_UID`/`PKEXEC_UID`;
2. использует его home/config для поиска Antigravity settings;
3. перед запуском IDE сбрасывает UID/GID обратно;
4. восстанавливает `HOME`, `USER`, `LOGNAME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`;
5. при наличии `/run/user/<uid>` восстанавливает `XDG_RUNTIME_DIR` и DBus session address.

Если исходного desktop user нельзя безопасно определить, launcher отказывается запускать Antigravity как root.

## Проверка ядра и host readiness

```bash
set -e

test -e /dev/net/tun && echo "TUN: OK" || echo "TUN: MISSING"
command -v getcap >/dev/null && \
  getcap "${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box" || true

ip -br link
ip -br addr
ip rule
ip route
ip -6 route
```

Если `/dev/net/tun` отсутствует, штатный Agent Tunnel start попробует загрузить `tun` через bounded helper. `sudo modprobe tun` нужен только как manual troubleshooting fallback.

## Проверка VPN-интерфейса

Agent Tunnel не стартует с несуществующим или DOWN upstream interface.

Примеры:

```text
wg0
wg-amnezia
amneziawg
amnezia
vpn0
tun0
tailscale0
```

В UI выбирайте фактический интерфейс, который присутствует в `ip link` и находится в состоянии `UP`.

## Проверка SAFE MODE

SAFE MODE не создаёт `antigravity-tun`:

```bash
ip link show antigravity-tun 2>/dev/null && echo "unexpected TUN" || echo "SAFE: no Agent TUN"
```

После запуска SAFE MODE:

```bash
curl -x http://127.0.0.1:7890 -I https://cloudcode-pa.googleapis.com/
```

Любой настоящий HTTP response code подтверждает, что CONNECT дошёл до backend; `404` на root path допустим и не означает сетевую ошибку.

## Проверка Agent Tunnel

После **«Подготовить Tunnel и запустить IDE»**:

```bash
ip -details link show antigravity-tun
ip addr show dev antigravity-tun
ip rule
ip route show table all | grep -E 'antigravity|172\.31\.255|20229|1900' || true

BIN="${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box"
getcap "$BIN"
```

Mixed proxy остаётся доступен для диагностики:

```bash
curl -x http://127.0.0.1:7890 -I https://oauth2.googleapis.com/
curl -x http://127.0.0.1:7890 -I https://cloudcode-pa.googleapis.com/
```

Но главный production signal находится в UI **Runtime network assurance** и `GET /api/attestation`, а не в одном факте доступности 7890.

## Runtime assurance

Система связывает:

```text
Antigravity PID tree
    ↓
live socket/source endpoint
    ↓
sing-box connection tracker
    ↓
vpn-direct
    ↓
external egress
```

UI отдельно показывает `Assurance` и `Isolation`. При включённом domain fallback возможно `VERIFIED` transport evidence при `ISOLATION-RELAXED` policy — эти состояния намеренно не смешиваются.

## Проверка cleanup

После **Остановить**:

```bash
if ip link show antigravity-tun >/dev/null 2>&1; then
  echo "ERROR: antigravity-tun still exists"
  exit 1
else
  echo "cleanup: OK"
fi
```

Managed sing-box получает `SIGTERM`; kill остаётся только bounded fallback. При исчезновении parent control plane Linux child получает `PDEATHSIG=SIGTERM`. Для SIGKILL/power-loss используется durable network journal и next-start conservative recovery.

## Что доказывает CI

Linux CI создаёт две независимые L3 uplink-сети в network namespaces:

```text
client namespace
├── sys0  10.251.0.2  metric 10
└── vpn0  10.250.0.2  metric 100

sink namespace
└── 203.0.113.10:18080
```

Настоящий pinned `sing-box 1.14.0` проверяется не только через `sing-box check`, но и runtime:

1. создаётся `antigravity-tun`;
2. mixed listener принадлежит managed PID;
3. `antigravity` выходит через `10.250.0.2`;
4. `language_server` выходит через `10.250.0.2`;
5. bundled `.../antigravity-bundle/node` выходит через `10.250.0.2` по `process_path_regex`;
6. ordinary probe остаётся на `10.251.0.2`;
7. PID/socket/outbound/external-egress chain проверяется end-to-end;
8. graceful/crash recovery проверяет owned cleanup и сохранение unrelated network state.

CI также выполняет `go test ./...`, `go vet ./...`, race detector, `riskcheck`, real sing-box config validation и Windows/Linux build matrix.

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

- privileged runtime/dual-egress proof сейчас strongest на Ubuntu amd64;
- Linux ARM64 остаётся build-only, пока нет native privileged runner — R-018;
- Debian/Fedora family и NetworkManager/systemd-networkd/Docker/Podman/VM combinations требуют расширенного runtime matrix — R-013/R-018;
- IPv6, UDP/QUIC и dual-stack DNS должны проверяться независимо — R-005;
- Windows ещё не имеет Linux-equivalent minimal privilege helper и полного external-egress Agent Tunnel runtime proof;
- автоматический Linux capability repair реализован, но отдельная ordinary-user upgrade/distro fixture для R-012 ещё требуется.
