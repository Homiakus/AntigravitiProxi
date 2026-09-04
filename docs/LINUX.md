# Linux — эксплуатация, права и проверка Agent Tunnel

Этот документ описывает Linux-специфичную часть AntigravitiProxi. Цель — запускать UI/control-plane от обычного пользователя и давать повышенные сетевые права только `sing-box`, а не Antigravity IDE.

## Поддерживаемая схема

```text
user session
├── AntigravitiProxi (обычный пользователь)
├── Antigravity IDE (обычный пользователь)
└── managed sing-box
      ├── CAP_NET_ADMIN
      ├── CAP_NET_RAW
      ├── TUN: antigravity-tun
      ├── auto_route
      └── auto_redirect / nftables
```

SAFE MODE не требует TUN и обычно не требует повышенных прав.

Agent Tunnel использует:

- `sing-box` 1.14.0;
- `/dev/net/tun`;
- `auto_route`;
- Linux `auto_redirect`;
- nftables / `nf_tables`;
- `nfnetlink_queue` для pre-match, если ядро/сборка sing-box использует этот путь;
- process matching для Antigravity/language server/helper процессов;
- `bind_interface` к явно выбранному VPN-интерфейсу.

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

Затем выдайте сетевые capabilities только этому бинарнику:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep \
  "${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box"

getcap "${XDG_CONFIG_HOME:-$HOME/.config}/AntigravitiProxi/bin/sing-box"
```

Ожидаемый результат содержит:

```text
cap_net_admin,cap_net_raw=ep
```

После обновления/replacement managed `sing-box` file capabilities могут быть сброшены файловой системой. В этом случае AntigravitiProxi остановит запуск Agent Tunnel на preflight и покажет команду `setcap`, которую нужно выполнить повторно.

## Не запускать IDE от root

Предпочтительный режим — AntigravitiProxi и Antigravity работают от обычного desktop-пользователя, а права находятся на `sing-box`.

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

Для типичного Ubuntu/Debian хоста полезно также проверить:

```bash
sudo modprobe nf_tables || true
sudo modprobe nfnetlink_queue || true
```

## Проверка VPN-интерфейса

Agent Tunnel больше не стартует с несуществующим или выключенным upstream-интерфейсом.

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
sudo nft list ruleset | grep -i -E 'sing-box|singbox|2022|2023|2024' || true
```

Параллельно:

```bash
curl -x http://127.0.0.1:7890 -I https://oauth2.googleapis.com/
curl -x http://127.0.0.1:7890 -I https://cloudcode-pa.googleapis.com/
```

## Проверка cleanup

Нормальная остановка Agent Tunnel должна убрать TUN и созданные sing-box route/nftables state.

После **Остановить Tunnel**:

```bash
if ip link show antigravity-tun >/dev/null 2>&1; then
  echo "ERROR: antigravity-tun still exists"
  exit 1
else
  echo "cleanup: OK"
fi
```

На Linux managed `sing-box` получает `SIGTERM`, а не немедленный `SIGKILL`, чтобы он успел убрать маршруты/nftables. Если Go control-plane аварийно исчезает, дочернему `sing-box` задан `PDEATHSIG=SIGTERM`, поэтому helper не должен оставаться бесхозным.

## Что проверяется CI

Для Linux есть отдельный privileged runtime smoke test в изолированном network namespace:

1. загружается pinned `sing-box 1.14.0`;
2. создаётся namespace;
3. создаётся тестовый VPN upstream `vpn0`;
4. запускается реальный Agent Tunnel;
5. проверяется появление `antigravity-tun`;
6. проверяется local mixed proxy port;
7. проверяется состояние Manager;
8. выполняется graceful stop;
9. проверяется исчезновение `antigravity-tun`.

Это дополняет обычные:

- `go test ./...`;
- `go vet ./...`;
- `sing-box check` generated config;
- Linux amd64 build;
- Linux arm64 build.

Runtime TUN smoke сейчас выполняется на Ubuntu GitHub runner amd64. ARM64 компилируется в CI, но privileged TUN runtime на реальном ARM64 runner пока не проверяется.

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

## Известные границы текущей проверки

- runtime smoke покрывает Ubuntu amd64; другие дистрибутивы пока проверяются компиляцией/общими Go-тестами, а не отдельным privileged runner для каждого дистрибутива;
- ARM64 Linux собирается, но TUN runtime CI сейчас amd64;
- CI проверяет реальное создание/cleanup TUN, но отдельный e2e-тест, который доказывает source egress именно конкретного PID Antigravity через реальный внешний VPN, остаётся следующим уровнем проверки;
- systemd-resolved, NetworkManager, nftables policy и корпоративные security agents могут отличаться между дистрибутивами — поэтому runtime preflight и явный VPN interface обязательны.
