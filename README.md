# BYE-BYE-BLOCK

Локальный адаптивный антицензурный прокси на Python: HTTP CONNECT + SOCKS5, DoH, подбор стратегий под конкретный хост, диагностика и read-only панель.

**Это не «обход всего».** Один инструмент не может гарантированно обходить DNS-, SNI-, IP-блокировки, throttling, whitelist и физическое отключение сети одновременно. Цель проекта — честно измерять, что происходит, пробовать безопасные стратегии, запоминать успешные и не ломать TLS.

## Что уже работает

- Локальный прокси `127.0.0.1:8844`: HTTP CONNECT, SOCKS5 CONNECT, absolute-form HTTP GET/HEAD.
- Стратегии:
  - `direct` — без изменений;
  - `tls-record-sni` — делит TLS ClientHello на две валидные TLS-записи внутри SNI;
  - `tls-record-mid` — делит ClientHello примерно посередине;
  - `tcp-sni` / `tcp-mid` — отправляет первый payload двумя TCP-сегментами;
  - `http-host-split` — делит HTTP-запрос внутри значения `Host`;
  - `http-header-case` — меняет регистр заголовка `Host`.
- Адаптивный кеш: последняя успешная стратегия для `host:port:protocol`, cooldown неудачных.
- DoH через Cloudflare/Google JSON API с проверкой TLS-сертификата, системный fallback.
- Диагностика `bbb probe`: DNS, TCP, TLS handshake с проверкой сертификата, HTTP-статус, сравнение стратегий.
- Внешний SOCKS5 upstream для случаев, когда нужен реальный туннель (IP-блокировки, whitelist).
- Read-only dashboard без телеметрии. Домены в событиях по умолчанию хешируются.
- Защита от открытого прокси: bind только на loopback, запрет private/IP-literal целей по умолчанию, ограниченные порты.

## Чего пока нет

- UDP/QUIC/HTTP/3 proxying.
- Kernel-level desync: fake packets, TTL/badseq/md5sig, NFQUEUE/WinDivert.
- Собственный VPN-сервер, VLESS/Reality, WireGuard, Shadowsocks.
- Обход физического отключения интернета или полноценного whitelist без доступного туннеля.
- Автоматическое доказательство «это именно РКН»: диагностика показывает симптомы, а не юридическую атрибуцию.

## Быстрый старт

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
bbb doctor
bbb run
```

Панель: <http://127.0.0.1:8787>. Прокси: `127.0.0.1:8844`.

Настройте браузер/систему на HTTP-прокси `127.0.0.1:8844` или SOCKS5 `127.0.0.1:8844`. Для Firefox можно указать SOCKS5 и включённый proxy DNS. Для Chrome/Edge удобнее системный HTTP-прокси или расширение управления прокси.

## Диагностика

```bash
bbb probe example.com
bbb probe example.com --port 443 --strategies direct,tls-record-sni,tcp-sni
bbb probe example.com --json --output reports/example.json
```

`probe` проверяет сертификат сервера. Если сертификат невалиден, стратегия считается неуспешной. Это намеренно: проект не занимается MITM и не отключает проверку TLS.

## Конфигурация

```bash
bbb config-example > config.local.toml
bbb run --config config.local.toml
```

Смотрите `examples/config.toml` и `examples/upstream-socks5.toml`.

Если у вас уже есть локальный SOCKS5-туннель (например, sing-box/xray/ssh -D), включите:

```toml
[upstream]
mode = "socks5"
host = "127.0.0.1"
port = 1080
remote_dns = true
```

В этом режиме BYE-BYE-BLOCK отправляет трафик в туннель. Без доступного туннеля IP-блокировку или whitelist он не «отменяет».

## Панель для предпросмотра

```bash
bbb dashboard --demo --host 0.0.0.0 --port 8787
```

`--demo` показывает синтетические данные и может слушать публичный интерфейс. Обычная панель и прокси должны оставаться на loopback.

## Тесты

```bash
python -m unittest discover -s tests -v
```

Интеграционные тесты поднимают локальный TLS-сервер с самоподписанным сертификатом и проверяют HTTP CONNECT, SOCKS5, TLS record split и TCP split.

## Документация

- [Матрица блокировок и обходов](docs/BLOCKING-MATRIX.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [Безопасность и границы](docs/SECURITY.md)
- [Дорожная карта](docs/ROADMAP.md)
- [Исходные материалы](docs/RESEARCH.md)

## Лицензия

MIT
