# Changelog

## 0.2.0
- Add native desktop window (Tkinter): Start/Stop, port/DNS/upstream settings, counters, log, copy address.
- Add optional Windows system-proxy toggle with restore on stop/exit.
- Add embeddable proxy engine for the GUI and tests for engine/settings/system-proxy guards.
- Add PyInstaller desktop entry point, icon, `build-windows.bat`, and Windows app build workflow.
- `start.bat` now opens the desktop program by default; console mode remains available via `--console`.
- Web dashboard is now optional/debug-only.

## 0.1.1
- Add Windows `start.bat` double-click launcher with local `.venv` bootstrap and doctor checks.
- Add `bbb run --open-browser` and CI coverage for the Windows launcher.

## 0.1.0
- Первый MVP: HTTP CONNECT/SOCKS5 локальный прокси.
- Стратегии direct, TLS record split, TCP split, HTTP Host split/header case.
- Адаптивный кеш стратегий и cooldown.
- DoH + system fallback, probe DNS/TCP/TLS/HTTP.
- SOCKS5 upstream.
- Read-only dashboard, demo mode.
- Тесты, документация, матрица блокировок.
