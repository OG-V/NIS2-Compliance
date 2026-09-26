"""An engagement folder: everything the consultant keeps for one client.

    <engagement>/
      target.yaml     systems in scope and the client's authorisation (as for the CLI)
      secrets.env     credentials entered in the app; never shown again, never in target.yaml
      results/        one folder per scan, with its report
      suggestions/    AI evidence suggestions per document, for the reviewer

The app edits target.yaml as plain data and validates it with the same model the scanner
uses, so a folder prepared in the app scans the same way from the command line.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import UTC, date, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from nis2scan.config import ASSET_SECTIONS, Target, load_target, parse_env_file

TARGET = "target.yaml"
SECRETS = "secrets.env"
RESULTS = "results"
SUGGESTIONS = "suggestions"
ROOT = Path(__file__).resolve().parents[3]  # the repository: catalog and profile live there
CATALOG = ROOT / "catalog" / "requirements"
PROFILE = ROOT / "catalog" / "profile.yaml"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nis2scan"
SECRET_SUFFIX = "_env"


def today() -> date:
    """Today in local time: engagement dates are calendar dates as agreed (as in scan.py)."""
    return datetime.now(UTC).astimezone().date()


class WorkspaceError(Exception):
    """A problem the consultant can act on, shown as is."""


# --- paths --------------------------------------------------------------------------------


def local_path(text: str) -> Path:
    r"""A folder as typed or pasted: C:\Users\... is translated when running under WSL."""
    text = text.strip().strip('"')
    if re.match(r"^[A-Za-z]:[\\/]", text) and shutil.which("wslpath"):
        out = subprocess.run(["wslpath", "-u", text], capture_output=True, text=True, check=False)
        if out.returncode == 0:
            return Path(out.stdout.strip())
    return Path(text).expanduser()


def windows_path(path: Path) -> str | None:
    """The Windows form of a path under WSL, for display and for opening in Explorer."""
    if not shutil.which("wslpath"):
        return None
    out = subprocess.run(["wslpath", "-w", str(path)], capture_output=True, text=True, check=False)
    return out.stdout.strip() if out.returncode == 0 else None


def places() -> list[dict]:
    """Shortcuts for the folder browser: home, and the Windows user folders under WSL."""
    found = [{"label": "Home", "path": str(Path.home())}]
    users = Path("/mnt/c/Users")
    if users.is_dir():
        for user in sorted(users.iterdir()):
            if user.name in ("Public", "Default", "Default User", "All Users"):
                continue
            for sub in ("Documents", "Desktop", "OneDrive"):
                if (user / sub).is_dir():
                    found.append({"label": f"Windows {sub}", "path": str(user / sub)})
    return found


def listing(path: Path, files: bool = False) -> dict:
    """Subfolders (and optionally files) of `path`, for the folder browser."""
    if not path.is_dir():
        raise WorkspaceError(f"{path} is not a folder")
    entries = []
    try:
        children = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except PermissionError:
        raise WorkspaceError(f"no permission to read {path}") from None
    for child in children:
        if child.name.startswith("."):
            continue
        try:
            is_dir = child.is_dir()
        except OSError:
            continue
        if is_dir or files:
            entries.append(
                {
                    "name": child.name,
                    "path": str(child),
                    "dir": is_dir,
                    "engagement": is_dir and (child / TARGET).is_file(),
                }
            )
    return {
        "path": str(path),
        "parent": str(path.parent) if path.parent != path else None,
        "entries": entries,
        "engagement": (path / TARGET).is_file(),
    }


def files(folder: Path, directory: str, limit: int = 400) -> list[str]:
    """Files under a documents folder (relative to the engagement if not absolute)."""
    base = (folder / local_path(directory)).resolve()
    if not base.is_dir():
        raise WorkspaceError(f"{directory} is not a folder")
    found = []
    for path in sorted(base.rglob("*")):
        rel = path.relative_to(base)
        if path.is_file() and not any(p.startswith(".") for p in rel.parts):
            found.append(rel.as_posix())
            if len(found) >= limit:
                break
    return found


def new_folder(parent: Path, name: str) -> Path:
    """Create an engagement folder; the name is used as typed, minus path separators."""
    name = re.sub(r'[\\/:*?"<>|]+', " ", name).strip().strip(".")
    if not name:
        raise WorkspaceError("give the folder a name")
    if not parent.is_dir():
        raise WorkspaceError(f"{parent} is not a folder")
    folder = parent / name
    if (folder / TARGET).exists():
        raise WorkspaceError(f"{folder} already holds an engagement: open it instead")
    folder.mkdir(exist_ok=True)
    return folder


# --- the engagement ---------------------------------------------------------------------------


def blank(folder: Path) -> dict:
    """A new target: named after the folder, with an empty authorisation to fill in."""
    return {
        "name": re.sub(r"[^a-z0-9]+", "-", folder.name.lower()).strip("-") or "client",
        "engagement": {
            "client": "",
            "authorised_by": "",
            "authorised_on": today().isoformat(),
            "valid_until": "",
            "active_tests": False,
        },
        "env_file": [SECRETS],
    }


def read_raw(folder: Path) -> dict:
    path = folder / TARGET
    if not path.is_file():
        return blank(folder)
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise WorkspaceError(f"{TARGET} is not valid YAML: {exc}") from None
    for section in ASSET_SECTIONS:  # the app always works with lists
        if isinstance(raw.get(section), dict):
            raw[section] = [raw[section]]
    return raw


def problems(raw: dict) -> list[dict]:
    """Validation problems in a raw target, each with its location, in the scanner's terms."""
    try:
        Target.model_validate(raw)
    except ValidationError as exc:
        return [
            {"loc": [str(p) for p in e["loc"]], "message": e["msg"].removeprefix("Value error, ")}
            for e in exc.errors()
        ]
    return []


def _clean(value):
    """Drop empty strings and empty lists, so target.yaml holds only what was entered."""
    if isinstance(value, dict):
        cleaned = {k: _clean(v) for k, v in value.items()}
        return {k: v for k, v in cleaned.items() if v not in ("", None, [], {})}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def save_raw(folder: Path, raw: dict) -> list[dict]:
    """Write target.yaml if it is valid; otherwise return the problems and write nothing."""
    raw = _clean(raw)
    env_files = raw.get("env_file") or []
    env_files = [env_files] if isinstance(env_files, str) else env_files
    if SECRETS not in env_files:
        raw["env_file"] = [*env_files, SECRETS]
    if found := problems(raw):
        return found
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / TARGET
    header = "# Scan target, maintained with the nis2scan app. Secrets are in secrets.env.\n"
    backup = folder / (TARGET + ".bak")
    if path.exists() and not path.read_text().startswith(header) and not backup.exists():
        shutil.copy2(path, backup)  # a hand-written original: keep it once, comments and all
    path.write_text(header + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))
    remember(folder, raw.get("engagement", {}).get("client") or raw.get("name", folder.name))
    return []


def target(folder: Path) -> Target:
    if not (folder / TARGET).is_file():
        raise WorkspaceError("save the engagement first: there is no target.yaml yet")
    try:
        return load_target(folder / TARGET)
    except (ValidationError, yaml.YAMLError) as exc:
        raise WorkspaceError(f"{TARGET} is not valid: {exc}") from None


# --- secrets ----------------------------------------------------------------------------------


def secret_name(section: str, asset: str, field: str) -> str:
    """The variable a credential is stored under, e.g. IDP_KEYCLOAK_ADMIN_PASSWORD."""
    base = field.removesuffix(SECRET_SUFFIX)
    return re.sub(r"[^A-Z0-9]+", "_", f"{section}_{asset}_{base}".upper()).strip("_")


def store_secret(folder: Path, name: str, value: str) -> None:
    """Set one NAME=value line in secrets.env, readable only by the current user."""
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
        raise WorkspaceError(f"{name!r} is not a valid variable name")
    if "\n" in value or "\r" in value:
        raise WorkspaceError("a credential cannot contain a line break")
    path = folder / SECRETS
    lines = path.read_text().splitlines() if path.exists() else []
    lines = [line for line in lines if not line.startswith(f"{name}=")]
    lines.append(f"{name}={value}")
    folder.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    path.write_text("\n".join(lines) + "\n")


def secrets_set(folder: Path, raw: dict) -> dict[str, bool]:
    """For each credential the target names: is it available? Values are never returned."""
    available = dict(os.environ)
    files = raw.get("env_file") or []
    for f in [files] if isinstance(files, str) else files:
        path = folder / f
        if path.is_file():
            available |= parse_env_file(path.read_text())
    names = {
        value
        for section in ASSET_SECTIONS
        for asset in raw.get(section) or []
        for key, value in asset.items()
        if key.endswith(SECRET_SUFFIX) and value
    }
    return {name: bool(available.get(name)) for name in sorted(names)}


# --- results ----------------------------------------------------------------------------------


def runs(folder: Path) -> list[dict]:
    """Earlier scans of this engagement, newest first."""
    out = []
    results = folder / RESULTS
    if not results.is_dir():
        return out
    for run in results.iterdir():
        meta_path = run / "scan.json"
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text())
            verdicts = json.loads((run / "verdicts.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        counts: dict[str, int] = {}
        for v in verdicts:
            counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
        out.append(
            {
                "id": run.name,
                "started_at": meta.get("started_at"),
                "verdicts": counts,
                "report": (run / "report.html").is_file(),
                "narrative": (run / "narrative.json").is_file(),
            }
        )
    return sorted(out, key=lambda r: r["started_at"] or "", reverse=True)


def run_dir(folder: Path, run_id: str) -> Path:
    path = (folder / RESULTS / run_id).resolve()
    if path.parent != (folder / RESULTS).resolve() or not (path / "scan.json").is_file():
        raise WorkspaceError(f"no scan {run_id!r} in this engagement")
    return path


# --- recent engagements -------------------------------------------------------------------------


def _recent_path() -> Path:
    return CONFIG_DIR / "recent.json"


def recent() -> list[dict]:
    try:
        items = json.loads(_recent_path().read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return [i for i in items if (Path(i["path"]) / TARGET).is_file()]


def remember(folder: Path, label: str) -> None:
    items = [i for i in recent() if i["path"] != str(folder)]
    items.insert(0, {"path": str(folder), "label": label, "opened": today().isoformat()})
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _recent_path().write_text(json.dumps(items[:12], indent=2))
