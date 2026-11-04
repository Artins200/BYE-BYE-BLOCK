#!/usr/bin/env python3
"""Cross-platform bootstrap used by start.bat.

Keeps Windows-specific console handling in start.bat and the actual setup logic
in Python so it can be tested on Linux CI as well. No admin rights are needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv"
STAMP = VENV / ".bbb-setup.json"


def venv_python() -> Path:
    return VENV / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")


def run(cmd: list[str | Path], **kwargs) -> int:
    printable = " ".join(str(part) for part in cmd)
    print(f"+ {printable}", flush=True)
    return subprocess.call([str(part) for part in cmd], cwd=ROOT, **kwargs)


def project_hash() -> str:
    digest = hashlib.sha256()
    digest.update(str(ROOT).encode("utf-8"))
    digest.update((ROOT / "pyproject.toml").read_bytes())
    return digest.hexdigest()


def package_importable(py: Path) -> bool:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [str(py), "-c", "import byebyeblock; print(byebyeblock.__version__)"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode == 0


def ensure_venv() -> Path:
    py = venv_python()
    if not py.exists():
        print("[1/3] Creating local .venv (no administrator rights)...", flush=True)
        try:
            venv.create(VENV, with_pip=True)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "Could not create .venv. Install standard Python from python.org "
                "with pip/venv support, or delete the broken .venv folder and retry."
            ) from exc
    result = subprocess.run(
        [str(py), "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RuntimeError(".venv contains an unsupported Python. Delete .venv and run start.bat again.")
    return py


def ensure_package(py: Path, reinstall: bool = False) -> None:
    stamp = {"project": project_hash(), "python": sys.version.split()[0], "mode": "editable"}
    if not reinstall and STAMP.exists() and package_importable(py):
        try:
            if json.loads(STAMP.read_text(encoding="utf-8")) == stamp:
                print("[2/3] Local environment is ready.", flush=True)
                return
        except (OSError, ValueError):
            pass
    print("[2/3] Installing BYE-BYE-BLOCK into .venv (first run may need internet)...", flush=True)
    code = run([py, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "-e", str(ROOT)])
    if code != 0:
        raise RuntimeError(
            "pip install failed. Check internet access and the error above, then run start.bat again. "
            "You can also try: .venv\\Scripts\\python.exe -m pip install -e ."
        )
    if not package_importable(py):
        raise RuntimeError("Installation finished but 'byebyeblock' cannot be imported.")
    STAMP.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap and start BYE-BYE-BLOCK")
    parser.add_argument("--setup-only", action="store_true", help="Prepare .venv and run doctor, then exit")
    parser.add_argument("--reinstall", action="store_true", help="Force reinstall into .venv")
    parser.add_argument("--console", action="store_true", help="Run the console proxy instead of the desktop window")
    parser.add_argument("--no-browser", action="store_true", help="Console mode only: do not open a browser dashboard")
    # parse_known_args lets users forward native CLI flags, e.g.
    # start.bat --console --config examples/config.toml --port 9000
    args, app_args = parser.parse_known_args(argv)

    if sys.version_info < (3, 11):
        print("Python 3.11+ is required.", file=sys.stderr)
        return 1

    try:
        py = ensure_venv()
        ensure_package(py, reinstall=args.reinstall)
        print("[3/3] Running checks...", flush=True)
        code = run([py, "-m", "byebyeblock", "doctor"])
        if code != 0:
            return code
        if args.setup_only:
            print("Setup complete. Start normally with start.bat (or bbb run).", flush=True)
            return 0
        if args.console:
            cmd: list[str | Path] = [py, "-m", "byebyeblock", "run"]
            if not args.no_browser:
                cmd.append("--open-browser")
            cmd.extend(app_args)
            print("Starting console proxy. Keep this window open; press Ctrl+C to stop.", flush=True)
            return run(cmd)
        cmd = [py, "-m", "byebyeblock", "gui"]
        cmd.extend(app_args)
        print("Starting BYE-BYE-BLOCK desktop window...", flush=True)
        return run(cmd)
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
