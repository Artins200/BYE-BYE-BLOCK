# Changelog

## Unreleased
- Add Windows `start.bat` double-click launcher with local `.venv` bootstrap, doctor checks and optional browser opening.
- Add `bbb run --open-browser` and CI coverage for the Windows launcher.

## 0.1.0
- Первый MVP: HTTP CONNECT/SOCKS5 локальный прокси.
- Стратегии direct, TLS record split, TCP split, HTTP Host split/header case.
- Адаптивный кеш стратегий и cooldown.
- DoH + system fallback, probe DNS/TCP/TLS/HTTP.
- SOCKS5 upstream.
- Read-only dashboard, demo mode.
- Тесты, документация, матрица блокировок.
