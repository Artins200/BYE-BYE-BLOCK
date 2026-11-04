"""Desktop entry point used by PyInstaller and `python -m byebyeblock.appentry`."""
from __future__ import annotations

import os
import sys


def main() -> int:
    # Windowed PyInstaller builds may not have stdio attached.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    if "--version" in sys.argv:
        from . import __version__

        print(__version__)
        return 0
    if "--selftest" in sys.argv:
        import argparse

        from .cli import cmd_doctor

        return cmd_doctor(argparse.Namespace(config=None))
    from .gui import main as gui_main

    return gui_main(smoke="--smoke" in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
