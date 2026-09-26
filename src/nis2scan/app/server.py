"""The desktop app's local server: the interface, a JSON API, and the reports.

It listens on 127.0.0.1 only. The window is opened with a one-time token that becomes
a same-site cookie; every request must carry it and name this host, so another website
open in the consultant's browser cannot drive the scanner or read results.
"""

from __future__ import annotations

import json
import mimetypes
import secrets
import shutil
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from nis2scan import __version__
from nis2scan.app import forms, jobs, register
from nis2scan.app import workspace as ws
from nis2scan.config import ASSET_SECTIONS

STATIC = files("nis2scan.app") / "static"
COOKIE = "nis2scan_session"
IDLE_LIMIT = 150  # seconds without a heartbeat before a closed window ends the app
REPORT_FILES = ("report.html", "report.json", "diff.html")


class App:
    def __init__(self, exit_when_closed: bool):
        self.token = secrets.token_urlsafe(24)
        self.exit_when_closed = exit_when_closed
        self.last_seen = time.time()
        self.closing_since: float | None = None
        self.server: ThreadingHTTPServer | None = None

    # --- lifecycle -----------------------------------------------------------------------------

    def watch(self) -> None:
        """End the app once its window has been closed and no job is running."""
        while True:
            time.sleep(5)
            if not self.exit_when_closed or jobs.busy():
                continue
            idle = time.time() - self.last_seen
            closed = self.closing_since and time.time() - self.closing_since > 8
            if idle > IDLE_LIMIT or closed:
                print("Window closed; stopping the nis2scan app.", flush=True)
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return

    # --- API ------------------------------------------------------------------------------------

    def state(self, _q) -> dict:
        return {
            "version": __version__,
            "recent": ws.recent(),
            "places": ws.places(),
            "api_key": bool(jobs.api_key()),
            "busy": jobs.busy(),
            "today": ws.today().isoformat(),
        }

    def schema(self, _q) -> dict:
        return forms.schema()

    def fs(self, q) -> dict:
        path = ws.local_path(q.get("path") or str(Path.home()))
        return ws.listing(path, files=q.get("files") == "1")

    def resolve(self, body) -> dict:
        path = ws.local_path(body["path"]).resolve()
        return {"path": str(path), "windows": ws.windows_path(path), "exists": path.is_dir()}

    def open(self, body) -> dict:
        folder = _folder(body, must_exist=False)
        raw = ws.read_raw(folder)
        exists = (folder / ws.TARGET).is_file()
        if exists:
            ws.remember(folder, (raw.get("engagement") or {}).get("client") or raw.get("name"))
        return {
            "folder": str(folder),
            "windows": ws.windows_path(folder),
            "exists": exists,
            "raw": raw,
            "problems": ws.problems(raw) if exists else [],
            "secrets": ws.secrets_set(folder, raw),
            "runs": ws.runs(folder),
        }

    def save(self, body) -> dict:
        folder = _folder(body, must_exist=False)
        raw = body["raw"]
        # Credentials typed in the form: stored in secrets.env, referenced by name.
        for item in body.get("secrets") or []:
            section, index, field = item["section"], int(item["index"]), item["field"]
            if section not in ASSET_SECTIONS or not field.endswith(ws.SECRET_SUFFIX):
                raise ws.WorkspaceError(f"unexpected credential field {section}.{field}")
            asset = raw[section][index]
            name = asset.get(field) or ws.secret_name(section, asset.get("name", ""), field)
            ws.store_secret(folder, name, item["value"])
            asset[field] = name
        problems = ws.save_raw(folder, raw)
        saved = not problems
        raw = ws.read_raw(folder) if saved else raw
        return {
            "saved": saved,
            "problems": problems,
            "raw": raw,
            "secrets": ws.secrets_set(folder, raw),
        }

    def runs(self, q) -> dict:
        return {"runs": ws.runs(_folder(q))}

    def job(self, body, kind: str) -> dict:
        folder = _folder(body)
        if jobs.busy():
            raise ws.WorkspaceError("another task is still running")
        work = {
            "access": (jobs.check_access, ()),
            "scan": (jobs.scan, ()),
            "narrate": (jobs.narrate, (body.get("run"),)),
            "suggest": (jobs.suggest, (body.get("documents") or [],)),
        }[kind]
        return {"job": jobs.start(kind, work[0], folder, *work[1]).id}

    def job_view(self, job_id: str, q) -> dict:
        job = jobs.JOBS.get(job_id)
        if not job:
            raise ws.WorkspaceError("unknown task")
        return job.view(int(q.get("since") or 0))

    def diff(self, body) -> dict:
        from nis2scan.report.compare import render_comparison

        folder = _folder(body)
        before, after = ws.run_dir(folder, body["before"]), ws.run_dir(folder, body["after"])
        _, _, c = render_comparison(before, after, after / "diff.html")
        return {
            "run": after.name,
            "fixed": len(c.fixed),
            "still_open": len(c.still_open),
            "new": len(c.new),
            "warnings": c.warnings,
        }

    def register_state(self, q) -> dict:
        return register.state(_folder(q))

    def register_create(self, body) -> dict:
        return {"register": register.create(_folder(body))}

    def register_review(self, body) -> dict:
        if body.get("replace"):
            register.update_review(_folder(body), body["replace"], body["entry"])
        else:
            register.add_review(_folder(body), body["entry"])
        return register.state(_folder(body))

    def register_batch(self, body) -> dict:
        register.apply_changes(_folder(body), body["changes"])
        return register.state(_folder(body))

    def document(self, q) -> dict:
        return register.document_text(_folder(q), q["path"])

    def register_delete(self, body) -> dict:
        register.delete_review(_folder(body), body["requirement"])
        return register.state(_folder(body))

    def suggestions(self, q) -> dict:
        folder = _folder(q)
        out = []
        path = folder / ws.SUGGESTIONS
        for f in sorted(path.glob("*.json")) if path.is_dir() else []:
            try:
                out.append(json.loads(f.read_text()))
            except (OSError, json.JSONDecodeError):
                continue
        return {"documents": out}

    def settings(self, body) -> dict:
        if key := body.get("api_key"):
            jobs.save_api_key(key)
        return {"api_key": bool(jobs.api_key())}

    def files(self, q) -> dict:
        return {"files": ws.files(_folder(q), q.get("dir") or ".")}

    def mkdir(self, body) -> dict:
        return {"path": str(ws.new_folder(ws.local_path(body["parent"]), body["name"]))}

    def shortcut(self, _body) -> dict:
        from nis2scan.app.desktop import install_shortcut

        return {"path": install_shortcut()}

    def reveal(self, body) -> dict:
        folder = _folder(body)
        path = ws.run_dir(folder, body["run"]) if body.get("run") else folder
        win = ws.windows_path(path)
        if win and shutil.which("explorer.exe"):
            subprocess.Popen(["explorer.exe", win])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", str(path)])
        else:
            raise ws.WorkspaceError(f"open {path} in your file manager")
        return {"opened": str(path)}


def _folder(params: dict, must_exist: bool = True) -> Path:
    raw = params.get("folder")
    if not raw:
        raise ws.WorkspaceError("no engagement folder given")
    folder = ws.local_path(raw).resolve()
    if must_exist and not folder.is_dir():
        raise ws.WorkspaceError(f"{folder} does not exist")
    if folder.exists() and not folder.is_dir():
        raise ws.WorkspaceError(f"{folder} is a file, not a folder")
    return folder


GET = {
    "/api/state": App.state,
    "/api/schema": App.schema,
    "/api/fs": App.fs,
    "/api/runs": App.runs,
    "/api/register": App.register_state,
    "/api/suggestions": App.suggestions,
    "/api/files": App.files,
    "/api/document": App.document,
}
POST = {
    "/api/resolve": App.resolve,
    "/api/open": App.open,
    "/api/save": App.save,
    "/api/diff": App.diff,
    "/api/register/create": App.register_create,
    "/api/register/review": App.register_review,
    "/api/register/delete": App.register_delete,
    "/api/register/batch": App.register_batch,
    "/api/settings": App.settings,
    "/api/reveal": App.reveal,
    "/api/mkdir": App.mkdir,
    "/api/shortcut": App.shortcut,
}


def handler(app: App, port: int):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"nis2scan/{__version__}"

        def log_message(self, fmt, *args):  # quiet: the console is not the interface
            if not self.path.startswith(("/api/jobs/", "/api/heartbeat")):
                sys.stderr.write(f"{self.command} {self.path.split('?')[0]} {args[1]}\n")

        # --- plumbing ------------------------------------------------------------------------

        def _send(self, status, body: bytes, ctype: str, headers: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, status=HTTPStatus.OK):
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _error(self, message: str, status=HTTPStatus.BAD_REQUEST):
            self._json({"error": message}, status)

        def _allowed(self) -> bool:
            if self.headers.get("Host") not in hosts:
                return False
            cookie = SimpleCookie(self.headers.get("Cookie") or "")
            return COOKIE in cookie and secrets.compare_digest(cookie[COOKIE].value, app.token)

        def _call(self, fn, *args):
            try:
                self._json(fn(app, *args))
            except ws.WorkspaceError as exc:
                self._error(str(exc))
            except (KeyError, ValueError, TypeError) as exc:
                self._error(f"bad request: {exc}")
            except Exception as exc:  # noqa: BLE001 - reported to the interface
                import traceback

                traceback.print_exc()
                self._error(f"{type(exc).__name__}: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

        # --- routes -------------------------------------------------------------------------

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[-1] for k, v in parse_qs(url.query).items()}
            if url.path == "/" and "t" in q:  # the launch link: swap the token for a cookie
                if self.headers.get("Host") in hosts and secrets.compare_digest(q["t"], app.token):
                    cookie = f"{COOKIE}={app.token}; HttpOnly; SameSite=Strict; Path=/"
                    return self._send(
                        HTTPStatus.SEE_OTHER, b"", "text/plain",
                        {"Location": "/", "Set-Cookie": cookie},
                    )  # fmt: skip
                return self._error("This link has expired. Start the app again.", 403)
            if not self._allowed():
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    b"Open the nis2scan app from its desktop shortcut.",
                    "text/plain",
                )
            app.last_seen, app.closing_since = time.time(), None
            if url.path in ("/", "/index.html"):
                return self._static("index.html")
            if url.path.startswith("/static/"):
                return self._static(url.path.removeprefix("/static/"))
            if url.path == "/report":
                return self._report(q)
            if url.path.startswith("/api/jobs/"):
                return self._call(App.job_view, url.path.rsplit("/", 1)[1], q)
            if url.path in GET:
                return self._call(GET[url.path], q)
            self._error("not found", HTTPStatus.NOT_FOUND)

        def do_POST(self):
            if not self._allowed():
                return self._error("forbidden", HTTPStatus.FORBIDDEN)
            path = urlparse(self.path).path
            if path == "/api/heartbeat":
                app.last_seen, app.closing_since = time.time(), None
                return self._json({"ok": True})
            if path == "/api/bye":
                app.closing_since = time.time()
                return self._json({"ok": True})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._error("expected JSON", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._error("invalid JSON")
            if path.startswith("/api/jobs/"):
                return self._call(App.job, body, path.rsplit("/", 1)[1])
            if path in POST:
                return self._call(POST[path], body)
            self._error("not found", HTTPStatus.NOT_FOUND)

        def _static(self, name: str):
            resource = STATIC.joinpath(*[p for p in name.split("/") if p not in ("", "..")])
            if not resource.is_file():
                return self._error("not found", HTTPStatus.NOT_FOUND)
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                ctype += "; charset=utf-8"
            self._send(HTTPStatus.OK, resource.read_bytes(), ctype)

        def _report(self, q):
            try:
                run = ws.run_dir(_folder(q), q.get("run", ""))
            except ws.WorkspaceError as exc:
                return self._error(str(exc), HTTPStatus.NOT_FOUND)
            name = q.get("file", "report.html")
            if name not in REPORT_FILES or not (run / name).is_file():
                return self._error("not found", HTTPStatus.NOT_FOUND)
            ctype = "text/html; charset=utf-8" if name.endswith(".html") else "application/json"
            self._send(HTTPStatus.OK, (run / name).read_bytes(), ctype)

    return Handler


def serve(port: int = 0, exit_when_closed: bool = True) -> tuple[ThreadingHTTPServer, App, str]:
    """Start the server in the background; returns it and the launch URL (with the token)."""
    app = App(exit_when_closed)
    server = ThreadingHTTPServer(("127.0.0.1", port), None)
    port = server.server_address[1]
    server.RequestHandlerClass = handler(app, port)
    server.daemon_threads = True
    app.server = server
    threading.Thread(target=app.watch, daemon=True, name="watch").start()
    return server, app, f"http://127.0.0.1:{port}/?t={app.token}"
