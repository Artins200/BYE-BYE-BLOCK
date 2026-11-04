"""Embeddable proxy engine: runs the asyncio proxy inside a worker thread.

Used by the desktop GUI; the CLI keeps its own asyncio entry point.
"""
from __future__ import annotations

import asyncio
import logging
import threading

from .config import Config
from .metrics import Metrics
from .proxy import ProxyServer


class Engine:
    def __init__(self, cfg: Config, metrics: Metrics | None = None, log_handler: logging.Handler | None = None):
        self.cfg = cfg
        self.metrics = metrics or Metrics(redact_domains=not cfg.log_domains)
        self.log_handler = log_handler
        self.bound: tuple[str, int] | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: ProxyServer | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, timeout: float = 10.0) -> tuple[str, int]:
        if self.running:
            raise RuntimeError("Engine is already running")
        self._ready.clear()
        self._error = None
        self.bound = None
        self._server = ProxyServer(self.cfg, self.metrics)
        self._thread = threading.Thread(target=self._run, name="bbb-engine", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            self.stop()
            raise TimeoutError("Proxy did not start in time")
        if self._error is not None:
            err = self._error
            self.stop()
            raise err
        assert self.bound is not None
        return self.bound

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        logger = logging.getLogger("byebyeblock")
        if self.log_handler is not None:
            logger.addHandler(self.log_handler)
            logger.setLevel(logging.INFO)
        try:
            self.bound = loop.run_until_complete(self._server.start())
        except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
            self._error = exc
            self._ready.set()
            if self.log_handler is not None:
                logger.removeHandler(self.log_handler)
            loop.close()
            self._loop = None
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                if self.log_handler is not None:
                    logger.removeHandler(self.log_handler)
                asyncio.set_event_loop(None)
                loop.close()
                self._loop = None

    def stop(self, timeout: float = 5.0) -> None:
        thread = self._thread
        loop = self._loop
        server = self._server
        if thread is None:
            return
        if loop is not None and server is not None:
            try:
                if not loop.is_closed():
                    asyncio.run_coroutine_threadsafe(server.stop(), loop).result(timeout)
            except Exception:  # noqa: BLE001 - best effort shutdown
                pass
            try:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                # The worker may have closed the loop after a failed start.
                pass
        thread.join(timeout)
        self._thread = None
        self._server = None
        self.bound = None
