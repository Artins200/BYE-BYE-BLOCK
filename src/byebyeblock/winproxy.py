"""Opt-in Windows system proxy toggle (per-user HKCU, no admin rights).

The previous state is saved and restored on stop/exit. Other platforms are a
no-op so the GUI can offer the checkbox only where it works.
"""
from __future__ import annotations

import sys

_STATE: dict | None = None
_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def supported() -> bool:
    return sys.platform == "win32"


def _notify() -> None:
    import ctypes

    wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
    wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


def _read_value(key, name: str):
    import winreg

    try:
        return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def apply(host: str, port: int) -> None:
    """Enable the system proxy. Raises if not on Windows."""
    global _STATE
    if not supported():
        raise RuntimeError("System proxy switching is only supported on Windows")
    if _STATE is not None:
        return
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        _STATE = {
            "enable": _read_value(key, "ProxyEnable"),
            "server": _read_value(key, "ProxyServer"),
            "override": _read_value(key, "ProxyOverride"),
        }
        override = _STATE["override"] or ""
        needed = ["localhost", "127.*", "[::1]", "<local>"]
        parts = [p for p in override.split(";") if p]
        for item in needed:
            if item not in parts:
                parts.append(item)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, ";".join(parts))
    _notify()


def restore() -> None:
    """Restore the pre-apply state. Safe to call when nothing was applied."""
    global _STATE
    if _STATE is None or not supported():
        _STATE = None
        return
    import winreg

    state, _STATE = _STATE, None
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        for name, value, kind in (
            ("ProxyEnable", state["enable"], winreg.REG_DWORD),
            ("ProxyServer", state["server"], winreg.REG_SZ),
            ("ProxyOverride", state["override"], winreg.REG_SZ),
        ):
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, kind, value)
    _notify()
