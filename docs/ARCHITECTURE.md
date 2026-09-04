# Архитектура AntigravitiProxi

## Цели

1. Перенести рабочую логику `Antigravity-Proxy-Manager-v5.ps1` в типобезопасное кроссплатформенное приложение.
2. Исключить глобальный proxy как обязательный механизм.
3. Разделить control plane, proxy data plane и платформенные функции.
4. Иметь один лёгкий бинарник с web UI.
5. Позволить наращивать Windows/Linux специфические адаптеры без размножения основной логики.

## Слои

```text
┌─────────────────────────────────────────────────────┐
│ Embedded PWA                                        │
│ HTML + CSS + JS + Service Worker                    │
└───────────────────────┬─────────────────────────────┘
                        │ localhost HTTP / SSE
┌───────────────────────▼─────────────────────────────┐
│ internal/app                                         │
│ status / actions / CSRF / orchestration              │
└───────┬─────────────────┬─────────────────┬──────────┘
        │                 │                 │
┌───────▼──────┐  ┌──────▼────────┐  ┌────▼──────────┐
│ proxy        │  │ diagnostics   │  │ antigravity  │
│ sing-box     │  │ DNS / DoH     │  │ settings     │
│ installer    │  │ interfaces    │  │ launcher     │
│ config       │  │ public IP     │  │ hosts        │
│ HTTP/SOCKS   │  └───────────────┘  └───────────────┘
└───────┬──────┘
        │
┌───────▼─────────────────────────────────────────────┐
│ sing-box data plane                                 │
│ mixed inbound → secure DoH → bind_interface → VPN   │
└─────────────────────────────────────────────────────┘
```

## Control plane

`cmd/antigraviti-proxi` поднимает web-сервер на loopback. UI ничего не знает о PowerShell/Bash и работает одинаково на обеих ОС.

API:

- `GET /api/status`
- `GET /api/events`
- `GET /api/diagnostics`
- `GET /api/logs`
- `POST /api/config`
- `POST /api/actions/install`
- `POST /api/actions/start`
- `POST /api/actions/stop`
- `POST /api/actions/test`
- `POST /api/actions/endpoint`
- `POST /api/actions/launch`
- `POST /api/actions/safe`
- `POST /api/actions/hosts/enable`
- `POST /api/actions/hosts/disable`

## Почему process-only proxy

PowerShell v5 доказал работоспособность локального proxy, но глобальный `User ENV + WinINET + WinHTTP` создавал нежелательную связь со сторонними программами, в частности Fusion 360.

Go-версия делает process isolation архитектурным инвариантом:

```text
System environment         unchanged
WinINET                    unchanged
WinHTTP                    unchanged
Fusion 360                 unchanged
Antigravity process env    proxy injected
Antigravity children       inherit proxy
```

## DNS

Диагностика использует три независимых представления:

1. системный resolver;
2. Cloudflare DoH с TLS `ServerName=cloudflare-dns.com`, но TCP dial pinned на `1.1.1.1:443`;
3. Google DoH с `ServerName=dns.google`, но TCP dial pinned на `8.8.8.8:443`.

Такой подход позволяет диагностировать ситуацию, когда локальный DNS возвращает для Google endpoint чужой IP.

## SOCKS5h

Для проверки remote DNS реализован небольшой SOCKS5 CONNECT client внутри проекта. Он передаёт hostname proxy-серверу как `ATYP=DOMAIN`, то есть соответствует поведению `curl --proxy socks5h://...`.

Это позволяет не тянуть `golang.org/x/net/proxy` только ради одного dialer.

## Установка sing-box

Алгоритм:

1. managed binary в data dir;
2. fallback — `PATH`;
3. если отсутствует — GitHub Release API `SagerNet/sing-box`;
4. выбирается asset по `GOOS/GOARCH`;
5. скачивается `.zip` или `.tar.gz`;
6. SHA-256 сравнивается с `digest` release asset;
7. архив безопасно извлекается с path traversal check;
8. binary устанавливается в `bin/`.

## Emergency hosts

Это не штатный data path. Он существует только для ситуации, когда конкретный процесс игнорирует proxy DNS.

Инварианты:

- IP берётся только через pinned DoH;
- перед записью создаётся backup;
- изменение ограничено блоком `ANTIGRAVITI-PROXI`;
- удаление затрагивает только этот блок;
- требуются системные права.

## PWA

UI использует:

- semantic HTML;
- responsive CSS;
- vanilla JS;
- service worker;
- manifest;
- SSE.

UI не требует build pipeline и хранится в `internal/webui/static`.
