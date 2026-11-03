# Исходные материалы

Проверено при подготовке MVP. Ссылки нужны для инженерных решений, а не для гарантии обхода.

## Проекты

- zapret: https://github.com/bol-van/zapret — multi-platform DPI bypass, nfqws/winws/tpws, desync, hostlist, blockcheck.
- GoodbyeDPI: https://github.com/ValdikSS/GoodbyeDPI — Windows, WinDivert, TCP fragmentation, fake packets, DNS redirection.
- ByeDPI: https://github.com/hufrea/byedpi — локальный SOCKS proxy, split/disorder/fake/tlsrec, auto mode.

На момент проверки репозитории zapret и GoodbyeDPI имели свежие коммиты/документацию; тезис «все сдались» не подтверждается открытой историей. Но даже активные проекты не обещают универсальный обход всех классов блокировок.

## Измерения и описания блокировок

- OONI, Russia report 2024: https://ooni.org/post/2024-russia-report/ — DNS manipulation, HTTP/TLS MITM, RST/timeout после ClientHello, TSPU, ECH/Cloudflare.
- TSPU paper: https://jedcrandall.github.io/courses/cse548spring2024/tspu-imc22.pdf — in-path/stateful TSPU, SNI/IP/QUIC triggers, разные blocking behaviors.
- Cloudflare, 2025: https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/ — throttling после ~16 KB, влияние на HTTP/1.1, HTTP/2, HTTP/3/QUIC.
- net4people/bbs issue 490: https://github.com/net4people/bbs/issues/490 — обсуждение нового метода и whitelist-подобного поведения.
- ECH research: https://www.petsymposium.org/foci/2025/foci-2025-0016.pdf — ограничения ECH как средства обхода, блокировка ECH к Cloudflare в РФ.

## Выводы для дизайна

1. Нужна диагностика по слоям: DNS, TCP/IP, TLS, HTTP, QUIC, объём ответа.
2. Нужен per-host выбор стратегии, а не один глобальный режим.
3. Нельзя считать любой таймаут цензурой: сервер, маршрут и CDN тоже ломаются.
4. IP-блокировки и whitelist требуют туннеля/другого маршрута.
5. TLS нельзя «чинить» отключением проверки сертификата.
6. Любые обещания универсального обхода должны сопровождаться измерениями и границами.
