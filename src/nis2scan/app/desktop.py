"""Opening the app as a desktop window, and installing its desktop shortcut.

The interface is a local web page shown in a browser's app mode: its own window, with
no tabs or address bar. On Windows with WSL (where the scanner and its tools run), the
shortcut starts the app inside WSL without a console window, and the app opens an
Edge window on the Windows side. Closing that window ends the app.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

from nis2scan.app import workspace as ws

TITLE = "NIS2 Evidence Console"
EDGE = Path("/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")
POWERSHELL = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
ICON = Path(__file__).parent / "static" / "icon.ico"
BROWSERS = ("microsoft-edge", "google-chrome", "chromium", "chromium-browser", "chrome")


def in_wsl() -> bool:
    return bool(os.environ.get("WSL_DISTRO_NAME")) and POWERSHELL.exists()


def _powershell(script: str) -> str:
    out = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
        cwd="/mnt/c",  # a Windows folder, so PowerShell does not warn about a UNC path
    )
    if out.returncode != 0:
        raise ws.WorkspaceError(out.stderr.strip() or "PowerShell failed")
    return out.stdout.strip()


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def open_window(url: str) -> str:
    """Show the app in a browser app window; returns how it was opened."""
    if in_wsl() and EDGE.exists():
        profile = _powershell("$env:LOCALAPPDATA") + r"\nis2scan\window"
        subprocess.Popen(
            [
                str(EDGE),
                f"--app={url}",
                f"--user-data-dir={profile}",  # its own window and taskbar entry
                "--window-size=1360,900",
                "--no-first-run",
                "--no-default-browser-check",
            ],
            cwd="/mnt/c",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return "Microsoft Edge app window"
    for name in BROWSERS:
        if path := shutil.which(name):
            subprocess.Popen(
                [path, f"--app={url}", "--window-size=1360,900"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return f"{name} app window"
    webbrowser.open(url)
    return "default browser"


def install_shortcut(folder: str | None = None) -> str:
    """Put a shortcut on the Windows desktop (or in `folder`) that starts the app in WSL."""
    if not in_wsl():
        raise ws.WorkspaceError(
            "the desktop shortcut is for Windows with WSL; elsewhere, run `nis2scan app`"
        )
    program = shutil.which("nis2scan") or str(Path(sys.executable).parent / "nis2scan")
    distro = os.environ["WSL_DISTRO_NAME"]
    icon = ws.windows_path(ICON)
    command = f"-d {distro} --cd {ws.ROOT} -- {program} app"
    where = _ps_quote(folder) if folder else "([Environment]::GetFolderPath('Desktop'))"
    script = f"""
$dir = Join-Path $env:LOCALAPPDATA 'nis2scan'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item -Force {_ps_quote(icon)} (Join-Path $dir 'app.ico')
$link = Join-Path {where} {_ps_quote(TITLE + ".lnk")}
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($link)
$s.TargetPath = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
$s.Arguments = '-NoProfile -WindowStyle Hidden -Command "Start-Process wsl.exe -WindowStyle Hidden -ArgumentList ''{command}''"'
$s.WindowStyle = 7
$s.IconLocation = (Join-Path $dir 'app.ico')
$s.Description = 'Internal NIS2 evidence scanner'
$s.Save()
$link
"""
    return _powershell(script)
