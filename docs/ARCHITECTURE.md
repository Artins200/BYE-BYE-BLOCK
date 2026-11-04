# Архитектура

```text
browser/app
   │ HTTP CONNECT / SOCKS5 / absolute HTTP
   ▼
ProxyServer (loopback only)
   ├─ parse target + validate port/private-address policy
   ├─ Resolver: DoH JSON (cert verified) → optional system fallback
   ├─ StrategyCache: host:port:protocol → preferred strategy + cooldown
   ├─ prepare(): direct / TLS record split / TCP split / HTTP Host split
   ├─ connect: direct TCP or upstream SOCKS5
   ├─ first-response check for safe-to-retry TLS/HTTP
   └─ bidirectional relay with half-close
Dashboard (read-only, separate port)
CLI: run / probe / doctor / dashboard / config-example / strategies
```

## Почему прокси, а не драйвер

MVP не требует WinDivert/NFQUEUE и админ-доступа. Это снижает риск сломать систему и упрощает аудит. Цена — нет доступа к произвольным пакетам, fake/TTL/badseq и UDP/QUIC.

## Адаптивность

1. Определяется протокол первого payload.
2. Выбирается список совместимых стратегий.
3. Если payload безопасно повторить (TLS ClientHello без early data или идемпотентный HTTP), пробуются стратегии по очереди.
4. Успех фиксируется только после первого ответа сервера; для probe — после проверенного TLS handshake и HTTP-статуса.
5. Неудачная стратегия уходит в cooldown.

POST/PUT/CONNECT с телом и TLS early data не ретраятся автоматически, чтобы не дублировать запросы.

## TLS

Прокси не терминирует TLS. Он меняет только транспортную нарезку первого ClientHello или HTTP-запроса. Сертификат проверяет конечный клиент. `bbb probe` использует OpenSSL/ssl с включённой проверкой сертификата.

## DNS

DoH JSON API совместим с Cloudflare и Google. Запросы идут по HTTPS с проверкой сертификата. Ответы кешируются с TTL. Системный fallback удобен, но может вернуть цензурированный ответ; это видно в отчёте как `system-fallback`.

## Upstream

`upstream.mode = "socks5"` отправляет соединения в уже существующий локальный/доверенный SOCKS5. Это путь для IP-блокировок и whitelist, когда туннель доступен. Проект не содержит VPN-сервер и не генерирует ключи.
