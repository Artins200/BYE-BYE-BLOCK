"""Desktop GUI for BYE-BYE-BLOCK.

A native window (Tkinter, bundled with Python on Windows). No browser, no web
server: the proxy engine runs in a worker thread and the window shows status,
counters and a log. Optionally toggles the Windows system proxy and restores
the previous state on stop/exit.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import sys
import threading
from pathlib import Path

from . import __version__
from .config import Config, ConfigError
from .engine import Engine
from .metrics import Metrics
from . import winproxy

APP_NAME = "BYE-BYE-BLOCK"


def settings_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "byebyeblock"


def load_settings() -> dict:
    path = settings_dir() / "settings.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data: dict) -> None:
    path = settings_dir() / "settings.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        pass


class QueueLogHandler(logging.Handler):
    def __init__(self, sink: queue.Queue):
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.put_nowait(self.format(record))
        except queue.Full:
            pass


def human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def build_config(port: int, dns_mode: str, use_upstream: bool, upstream_port: int) -> Config:
    cfg = Config()
    cfg.proxy.host = "127.0.0.1"
    cfg.proxy.port = port
    cfg.dns.mode = dns_mode
    cfg.dashboard.enabled = False
    cfg.strategy.mode = "auto"
    if use_upstream:
        cfg.upstream.mode = "socks5"
        cfg.upstream.host = "127.0.0.1"
        cfg.upstream.port = upstream_port
    cfg.validate()
    return cfg


class Application:
    POLL_MS = 400

    def __init__(self, root, config_path: Path | None = None):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.root = root
        self.config_path = config_path
        self.events: queue.Queue = queue.Queue(maxsize=2000)
        self.results: queue.Queue = queue.Queue()
        self.engine: Engine | None = None
        self.metrics = Metrics()
        self.busy = False
        self.system_proxy_applied = False

        stored = load_settings()
        initial = Config.load(config_path) if config_path else Config()
        self.port_var = tk.StringVar(value=str(stored.get("port", initial.proxy.port)))
        self.dns_var = tk.StringVar(value=stored.get("dns_mode", initial.dns.mode))
        self.upstream_var = tk.BooleanVar(value=bool(stored.get("use_upstream", initial.upstream.mode == "socks5")))
        self.upstream_port_var = tk.StringVar(value=str(stored.get("upstream_port", initial.upstream.port)))
        self.sysproxy_var = tk.BooleanVar(value=bool(stored.get("system_proxy", False)) and winproxy.supported())

        root.title(f"{APP_NAME} {__version__}")
        root.geometry("720x600")
        root.minsize(640, 540)
        self._set_icon()

        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Status.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Big.TButton", font=("Segoe UI", 11, "bold"), padding=8)

        outer = ttk.Frame(root, padding=14)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x")
        ttk.Label(head, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(side="left")
        self.state_label = ttk.Label(head, text="Остановлено", style="Status.TLabel", foreground="#b91c1c")
        self.state_label.pack(side="right")

        ttk.Separator(outer).pack(fill="x", pady=10)

        controls = ttk.Frame(outer)
        controls.pack(fill="x")
        self.toggle_btn = ttk.Button(controls, text="Старт", style="Big.TButton", command=self.toggle)
        self.toggle_btn.pack(side="left")
        ttk.Label(controls, text="Порт:").pack(side="left", padx=(16, 4))
        self.port_entry = ttk.Entry(controls, textvariable=self.port_var, width=8)
        self.port_entry.pack(side="left")
        ttk.Label(controls, text="DNS:").pack(side="left", padx=(16, 4))
        self.dns_combo = ttk.Combobox(controls, textvariable=self.dns_var, values=["doh", "system"], width=8, state="readonly")
        self.dns_combo.pack(side="left")

        opts = ttk.Frame(outer)
        opts.pack(fill="x", pady=(10, 0))
        self.sysproxy_check = ttk.Checkbutton(
            opts,
            text="Включать системный прокси Windows (вернуть как было при остановке)",
            variable=self.sysproxy_var,
            command=self._on_sysproxy_toggle,
        )
        self.sysproxy_check.pack(anchor="w")
        if not winproxy.supported():
            self.sysproxy_check.state(["disabled"])
            self.sysproxy_var.set(False)

        up = ttk.Frame(opts)
        up.pack(anchor="w", pady=(4, 0))
        ttk.Checkbutton(up, text="Через внешний SOCKS5-туннель 127.0.0.1:", variable=self.upstream_var).pack(side="left")
        ttk.Entry(up, textvariable=self.upstream_port_var, width=8).pack(side="left", padx=4)

        ttk.Separator(outer).pack(fill="x", pady=10)

        stats = ttk.Frame(outer)
        stats.pack(fill="x")
        self.stat_labels: dict[str, object] = {}
        for key, title in (
            ("connections", "Соединения"),
            ("successes", "Успешно"),
            ("failures", "Ошибки"),
            ("traffic", "Трафик"),
        ):
            cell = ttk.Frame(stats)
            cell.pack(side="left", expand=True, fill="x")
            ttk.Label(cell, text=title, foreground="#555").pack(anchor="w")
            label = ttk.Label(cell, text="0", font=("Segoe UI", 13, "bold"))
            label.pack(anchor="w")
            self.stat_labels[key] = label

        self.address_label = ttk.Label(outer, text="Прокси выключен", foreground="#555")
        self.address_label.pack(anchor="w", pady=(10, 4))

        ttk.Label(outer, text="Журнал:").pack(anchor="w")
        from tkinter import scrolledtext

        self.log = scrolledtext.ScrolledText(outer, height=12, wrap="word", state="disabled", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(8, 0))
        ttk.Button(bottom, text="Копировать адрес", command=self._copy_address).pack(side="left")
        ttk.Button(bottom, text="Очистить журнал", command=self._clear_log).pack(side="left", padx=6)
        ttk.Button(bottom, text="Открыть папку настроек", command=self._open_settings).pack(side="left")

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._log_line(f"{APP_NAME} {__version__}. Нажмите «Старт».")
        self._log_line("Системный прокси по умолчанию не меняется.")
        root.after(self.POLL_MS, self._poll)

    def _set_icon(self) -> None:
        try:
            base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
            for candidate in (base / "assets" / "icon.png", Path(__file__).parent / "static" / "logo.png"):
                if candidate.exists():
                    self._icon = self.tk.PhotoImage(file=str(candidate))
                    self.root.iconphoto(True, self._icon)
                    return
        except Exception:  # noqa: BLE001 - icon is cosmetic
            pass

    # ---------- engine control ----------

    def toggle(self) -> None:
        if self.busy:
            return
        if self.engine and self.engine.running:
            self._stop()
        else:
            self._start()

    def _start(self) -> None:
        try:
            port = int(self.port_var.get())
            upstream_port = int(self.upstream_port_var.get())
            cfg = build_config(port, self.dns_var.get(), self.upstream_var.get(), upstream_port)
        except (ValueError, ConfigError) as exc:
            self._error(f"Неверные настройки: {exc}")
            return
        self.busy = True
        self.toggle_btn.state(["disabled"])
        self.state_label.configure(text="Запуск…", foreground="#b45309")
        self._log_line("Запуск прокси…")
        handler = QueueLogHandler(self.events)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        self.metrics = Metrics(redact_domains=not cfg.log_domains)
        engine = Engine(cfg, self.metrics, handler)

        def worker():
            try:
                bound = engine.start()
                self.results.put(("started", bound, engine))
            except Exception as exc:  # noqa: BLE001
                self.results.put(("error", str(exc), engine))

        threading.Thread(target=worker, daemon=True).start()

    def _stop(self) -> None:
        engine = self.engine
        if engine is None:
            return
        self.busy = True
        self.toggle_btn.state(["disabled"])
        self.state_label.configure(text="Остановка…", foreground="#b45309")
        self._restore_system_proxy()

        def worker():
            try:
                engine.stop()
                self.results.put(("stopped", None, engine))
            except Exception as exc:  # noqa: BLE001
                self.results.put(("stopped", str(exc), engine))

        threading.Thread(target=worker, daemon=True).start()

    def _on_started(self, bound, engine: Engine) -> None:
        self.engine = engine
        self.busy = False
        self.toggle_btn.state(["!disabled"])
        self.toggle_btn.configure(text="Стоп")
        self.state_label.configure(text="Работает", foreground="#15803d")
        host, port = bound
        self.address_label.configure(text=f"Прокси: {host}:{port}  (HTTP CONNECT и SOCKS5)")
        self._set_inputs_state("disabled")
        self._log_line(f"Прокси запущен на {host}:{port}")
        if self.sysproxy_var.get() and winproxy.supported():
            try:
                winproxy.apply(host, port)
                self.system_proxy_applied = True
                self._log_line("Системный прокси Windows включён.")
            except Exception as exc:  # noqa: BLE001
                self._log_line(f"Не удалось включить системный прокси: {exc}")
        else:
            self._log_line(f"Укажите в браузере прокси {host}:{port}.")
        self._save()

    def _on_stopped(self) -> None:
        self.engine = None
        self.busy = False
        self.toggle_btn.state(["!disabled"])
        self.toggle_btn.configure(text="Старт")
        self.state_label.configure(text="Остановлено", foreground="#b91c1c")
        self.address_label.configure(text="Прокси выключен")
        self._set_inputs_state("!disabled")
        self._log_line("Прокси остановлен.")
        self._save()

    def _set_inputs_state(self, state: str) -> None:
        self.port_entry.state([state])
        self.dns_combo.state([state] if state == "disabled" else ["readonly"])
        self.sysproxy_check.state([state] if winproxy.supported() else ["disabled"])

    def _on_sysproxy_toggle(self) -> None:
        if not (self.engine and self.engine.running and self.engine.bound):
            self._save()
            return
        host, port = self.engine.bound
        if self.sysproxy_var.get():
            try:
                winproxy.apply(host, port)
                self.system_proxy_applied = True
                self._log_line("Системный прокси Windows включён.")
            except Exception as exc:  # noqa: BLE001
                self._log_line(f"Не удалось включить системный прокси: {exc}")
        else:
            self._restore_system_proxy()
        self._save()

    def _restore_system_proxy(self) -> None:
        if self.system_proxy_applied:
            try:
                winproxy.restore()
                self._log_line("Системный прокси возвращён в исходное состояние.")
            except Exception as exc:  # noqa: BLE001
                self._log_line(f"Не удалось вернуть системный прокси: {exc}")
            self.system_proxy_applied = False

    # ---------- ui plumbing ----------

    def _poll(self) -> None:
        while True:
            try:
                kind, payload, engine = self.results.get_nowait()
            except queue.Empty:
                break
            if kind == "started":
                self._on_started(payload, engine)
            elif kind == "stopped":
                self._on_stopped()
            else:
                self.busy = False
                self.engine = None
                self.toggle_btn.state(["!disabled"])
                self.toggle_btn.configure(text="Старт")
                self.state_label.configure(text="Ошибка", foreground="#b91c1c")
                self._set_inputs_state("!disabled")
                self._error(f"Не удалось запустить: {payload}")
        while True:
            try:
                line = self.events.get_nowait()
            except queue.Empty:
                break
            self._log_line(line)
        snap = self.metrics.snapshot()
        self.stat_labels["connections"].configure(text=str(snap["connections"]))
        self.stat_labels["successes"].configure(text=str(snap["successes"]))
        self.stat_labels["failures"].configure(text=str(snap["failures"]))
        self.stat_labels["traffic"].configure(text=human_bytes(snap["bytes_up"] + snap["bytes_down"]))
        self.root.after(self.POLL_MS, self._poll)

    def _log_line(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        if int(self.log.index("end-1c").split(".")[0]) > 500:
            self.log.delete("1.0", "100.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _copy_address(self) -> None:
        if self.engine and self.engine.bound:
            host, port = self.engine.bound
            self.root.clipboard_clear()
            self.root.clipboard_append(f"{host}:{port}")
            self._log_line("Адрес скопирован в буфер обмена.")

    def _open_settings(self) -> None:
        folder = settings_dir()
        folder.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(folder))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess

                subprocess.Popen(["open", str(folder)])
            else:
                import subprocess

                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as exc:  # noqa: BLE001
            self._log_line(f"Папка настроек: {folder} ({exc})")

    def _error(self, message: str) -> None:
        self._log_line(message)
        from tkinter import messagebox

        messagebox.showerror(APP_NAME, message, parent=self.root)

    def _save(self) -> None:
        save_settings(
            {
                "port": self.port_var.get(),
                "dns_mode": self.dns_var.get(),
                "use_upstream": self.upstream_var.get(),
                "upstream_port": self.upstream_port_var.get(),
                "system_proxy": self.sysproxy_var.get(),
            }
        )

    def on_close(self) -> None:
        self._restore_system_proxy()
        self._save()
        if self.engine and self.engine.running:
            self.engine.stop()
        self.root.destroy()


def main(config_path: Path | None = None, smoke: bool = False) -> int:
    import atexit

    atexit.register(winproxy.restore)
    try:
        import tkinter as tk
    except ImportError:
        print(
            "Tkinter is not available. On Windows reinstall Python from python.org "
            "with the tcl/Tk option enabled.",
            file=sys.stderr,
        )
        return 1
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"No display available: {exc}", file=sys.stderr)
        return 1
    app = Application(root, config_path)
    if smoke:
        def finish():
            app.on_close()

        root.after(300, finish)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
