"""Backup adapters, how their tools are run, detection and the backup check."""

import json
from datetime import UTC, datetime

import pytest
from conftest import FIXTURES

from nis2scan import adapters
from nis2scan.adapters import backup as backup_module
from nis2scan.adapters.backup import ADAPTERS, BackupEvidence, BackupSet, Snapshot, run
from nis2scan.adapters.backup.borg import as_utc
from nis2scan.adapters.backup.restic import parse_time
from nis2scan.checks.operations import backups_encrypted, recent_backup
from nis2scan.collectors.backup import detect
from nis2scan.config import BackupTarget, load_profile
from nis2scan.registry import CollectorError

PROFILE = load_profile(FIXTURES.parent.parent.parent / "catalog" / "profile.yaml")


def recorded(profile, tool):
    return json.loads((FIXTURES / profile / "backup_snapshots" / f"{tool}.json").read_text())


@pytest.mark.parametrize("profile", ["weak", "hardened"])
@pytest.mark.parametrize("tool", ["restic", "borg"])
def test_recorded_evidence_is_the_normalised_raw_response(profile, tool):
    ev = recorded(profile, tool)
    assert ADAPTERS[tool].normalize(ev["raw"]).model_dump(mode="json") == ev["backup"]


def test_live_borg_repositories():
    (weak,) = ADAPTERS["borg"].normalize(recorded("weak", "borg")["raw"]).sets
    assert weak.encrypted is False and weak.newest.time == datetime(2025, 3, 15, 3, tzinfo=UTC)
    (hardened,) = ADAPTERS["borg"].normalize(recorded("hardened", "borg")["raw"]).sets
    assert hardened.encrypted is True


def test_restic_groups_snapshots_by_host_and_paths():
    raw = {
        "source": "r",
        "snapshots": [
            {"time": "2026-09-25T02:00:00Z", "hostname": "web", "paths": ["/srv"], "short_id": "a"},
            {"time": "2026-09-26T02:00:00Z", "hostname": "web", "paths": ["/srv"], "short_id": "b"},
            {
                "time": "2025-01-01T02:00:00Z",
                "hostname": "db",
                "paths": ["/var/lib/pg"],
                "short_id": "c",
            },
        ],
    }
    repo = ADAPTERS["restic"].normalize(raw)
    assert [(s.name, len(s.snapshots)) for s in repo.sets] == [
        ("db:/var/lib/pg", 1),
        ("web:/srv", 2),
    ]
    assert repo.stalest.name == "db:/var/lib/pg"  # the stopped job is not hidden


@pytest.mark.parametrize(
    "mode, encrypted",
    [
        ("none", False),
        ("authenticated-blake2", False),
        ("repokey", True),
        ("keyfile-blake2", True),
        (None, None),
    ],
)
def test_borg_encryption_modes(mode, encrypted):
    raw = {"source": "x", "encryption": mode, "archives": []}
    assert ADAPTERS["borg"].normalize(raw).sets[0].encrypted is encrypted


def test_times():
    assert parse_time("2026-09-25T01:04:24.615856123+02:00") == datetime(
        2026, 9, 24, 23, 4, 24, 615856, tzinfo=UTC
    )
    assert parse_time("2025-06-01T02:00:00Z").tzinfo is not None
    assert as_utc("2025-03-15T03:00:00.000000") == datetime(2025, 3, 15, 3, tzinfo=UTC)


# --- running the tool --------------------------------------------------------------


def test_container_runs_use_docker_exec(monkeypatch):
    calls = []
    monkeypatch.setattr(backup_module, "docker", lambda *args, timeout: calls.append(args) or "out")
    assert run(BackupTarget(container="b1"), ["restic", "version"], {}, None) == "out"
    assert calls == [("exec", "b1", "restic", "version")]


def test_local_runs_pass_the_password_in_the_environment(monkeypatch):
    seen = {}

    class Done:
        returncode, stdout, stderr = 0, "[]", ""

    def fake_run(argv, **kwargs):
        seen["argv"], seen["env"] = argv, kwargs["env"]
        return Done()

    monkeypatch.setattr(backup_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(backup_module.subprocess, "run", fake_run)
    target = BackupTarget(repository="sftp:backup@store:/repo", password_env="RESTIC_PW")
    ADAPTERS["restic"].fetch(target, lambda name: "s3cret")
    assert seen["argv"] == ["restic", "snapshots", "--json"]  # never the password
    assert seen["env"]["RESTIC_PASSWORD"] == "s3cret"
    assert seen["env"]["RESTIC_REPOSITORY"] == "sftp:backup@store:/repo"


def test_local_runs_need_the_tool_installed(monkeypatch):
    monkeypatch.setattr(backup_module.shutil, "which", lambda name: None)
    with pytest.raises(CollectorError, match="borg is not installed on the scanning host"):
        run(BackupTarget(repository="/repo"), ["borg", "list", "--json"], {}, None)


def test_a_backup_asset_needs_a_way_in():
    with pytest.raises(ValueError, match="needs either container or repository"):
        BackupTarget()


# --- detection -----------------------------------------------------------------------


def test_detection_asks_each_tool_for_its_version(monkeypatch):
    replies = {"restic": CollectorError("not found"), "borg": "borg 1.4.4\n"}

    def fake(backup, argv, env, secret, timeout=120):
        reply = replies[argv[0]]
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(adapters.backup.restic, "run", fake)
    monkeypatch.setattr(adapters.backup.borg, "run", fake)
    found = detect(BackupTarget(container="b1"), None)
    assert (found["product"], found["method"]) == ("borg", "borg 1.4.4 found in container b1")


def test_unknown_or_missing_tool(monkeypatch):
    with pytest.raises(CollectorError, match="unknown backup tool 'veeam'"):
        detect(BackupTarget(container="b1", product="veeam"), None)
    for tool in ("restic", "borg"):
        monkeypatch.setattr(ADAPTERS[tool], "recognise", lambda backup, secret: None)
    with pytest.raises(CollectorError, match="no supported backup tool found"):
        detect(BackupTarget(container="b1"), None)


# --- the check -----------------------------------------------------------------------

NOW = datetime(2026, 9, 26, 12, tzinfo=UTC)


OLD, FRESH = datetime(2025, 1, 1, tzinfo=UTC), datetime(2026, 9, 26, 2, tzinfo=UTC)


def evidence(*sets):
    """sets: (name, [times], encrypted)"""
    repo = BackupEvidence(
        repository="r",
        sets=[
            BackupSet(name=n, snapshots=[Snapshot(time=t) for t in times], encrypted=enc)
            for n, times, enc in sets
        ],
    )
    return {"backup": repo.model_dump(mode="json")}


def test_newest_snapshot_of_a_set_decides():
    assert recent_backup(evidence(("a", [OLD, FRESH], True)), PROFILE, NOW).status == "pass"
    assert recent_backup(evidence(("a", [OLD], True)), PROFILE, NOW).status == "fail"


def test_the_stalest_set_decides_and_is_named():
    result = recent_backup(evidence(("web", [FRESH], True), ("db", [OLD], True)), PROFILE, NOW)
    assert result.status == "fail" and result.message.endswith("days old (db)")
    assert result.observed["set"] == "db"


def test_no_snapshots_fail():
    assert recent_backup(evidence(), PROFILE, NOW).message == "No backup snapshots exist"
    result = recent_backup(evidence(("web", [FRESH], True), ("db", [], True)), PROFILE, NOW)
    assert result.message == "No backup snapshots exist (db)"


def test_encryption_check():
    assert backups_encrypted(evidence(("a", [FRESH], True)), PROFILE, NOW).status == "pass"
    single = backups_encrypted(evidence(("a", [FRESH], False)), PROFILE, NOW)
    assert (single.status, single.message) == ("fail", "The backups are not encrypted")
    several = backups_encrypted(evidence(("a", [FRESH], True), ("b", [FRESH], False)), PROFILE, NOW)
    assert several.message == "1 backup set(s) are not encrypted"
    assert several.observed["unencrypted_sets"] == ["b"]


def test_unknown_encryption_is_not_a_pass():
    result = backups_encrypted(evidence(("a", [FRESH], None)), PROFILE, NOW)
    assert result.status == "error" and "does not report" in result.message
