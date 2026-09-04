# AntigravitiProxi

Кроссплатформенная Go-реализация `Antigravity-Proxy-Manager-v5.ps1` для Windows и Linux.

Основная идея: **не менять глобальный proxy системы**, а запускать Antigravity IDE с proxy только в окружении его процесса. Это сохраняет работоспособность Fusion 360, Autodesk Access и других программ, которые могут ломаться при глобальных `WinINET` / `WinHTTP` / `HTTP_PROXY` настройках.

## Что уже реализовано

- один статический Go-бинарник без runtime-зависимостей;
- Windows и Linux;
- лёгкий web UI на стандартном `net/http`, без React/Node/npm;
- UI встроен в бинарник через `embed`;
- PWA: manifest + service worker, адаптивный интерфейс;
- локальный control plane по умолчанию только на `127.0.0.1:48765`;
- local mixed proxy `HTTP CONNECT + SOCKS5` на `127.0.0.1:7890` через `sing-box`;
- автономная установка официального `sing-box` из GitHub Releases с проверкой `SHA-256 digest`;
- Cloudflare DoH и Google DoH;
- `bind_interface` к выбранному VPN-интерфейсу;
- автоматическое обнаружение вероятных VPN-интерфейсов (`Amnezia`, `WireGuard`, `wg`, `tun`, `Tailscale`, `Outline`);
- диагностика System DNS ↔ pinned Cloudflare DoH ↔ pinned Google DoH;
- HTTP proxy tests и собственный SOCKS5h remote-DNS test;
- принудительный `jetski.cloudCodeUrl = https://cloudcode-pa.googleapis.com`;
- process-only запуск Antigravity IDE;
- emergency hosts override с backup и rollback;
- live events через SSE и live sing-box logs;
- CSRF-защита локальных write API;
- GitHub Actions для тестов, Windows/Linux builds и release artifacts.

## SAFE MODE

Рекомендуемый режим в web UI — **SAFE MODE**:

```text
Antigravity IDE
      │
      │ process-only HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
      ▼
127.0.0.1:7890
      │
      ▼
   sing-box
      │
      ├── DNS → pinned DoH
      │
      └── outbound → выбранный VPN interface
                         │
                         ▼
                       Google

Fusion 360 / Autodesk / другие приложения
      │
      └──────────────→ обычная системная сеть / VPN
```

Глобальные WinINET/WinHTTP proxy-настройки, которые вызывали проблемы с Fusion 360, в новой архитектуре **не используются по умолчанию**.

## Быстрый запуск

Нужен Go 1.23+.

```bash
git clone https://github.com/Homiakus/AntigravitiProxi.git
cd AntigravitiProxi
go run ./cmd/antigraviti-proxi
```

После запуска откроется `http://127.0.0.1:48765/`.

Без автоматического открытия браузера:

```bash
go run ./cmd/antigraviti-proxi --no-browser
```

## Сборка

```bash
CGO_ENABLED=0 go build -trimpath -o antigraviti-proxi ./cmd/antigraviti-proxi
```

Windows cross-build:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o antigraviti-proxi-windows-amd64.exe ./cmd/antigraviti-proxi
```

## Первый запуск

1. Включить рабочий VPN.
2. Запустить `AntigravitiProxi`.
3. Выбрать VPN-интерфейс (например `AmneziaVPN`).
4. Нажать **Сохранить**.
5. Нажать **SAFE MODE**.
6. Программа найдёт/установит `sing-box`, создаст DoH+VPN route, поднимет local proxy, применит production Cloud Code endpoint и запустит Antigravity с proxy только внутри процесса IDE.

## Почему web UI лёгкий

Web-слой: `net/http + embed + HTML/CSS/vanilla JS + SSE`. Нет Electron, Node.js, npm, React/Vue, отдельного web-сервера, SQLite или CGO.

## Данные приложения

Используется `os.UserConfigDir()`:

- Windows обычно `%LOCALAPPDATA%\AntigravitiProxi`;
- Linux обычно `~/.config/AntigravitiProxi`.

Внутри: `config.json`, `sing-box.json`, логи, `bin/sing-box[.exe]`, `backups/`.

## Безопасность

- UI по умолчанию только на loopback;
- write API требуют SameSite cookie + CSRF header;
- TLS verification не отключается;
- `sing-box` проверяется по digest официального GitHub Release;
- emergency hosts override выключен по умолчанию;
- глобальный system proxy не используется стандартным SAFE MODE.

Подробнее: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/V5_FEATURE_MAP.md`](docs/V5_FEATURE_MAP.md), [`MASTER_PLAN.md`](MASTER_PLAN.md).
