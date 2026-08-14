#!/usr/bin/python3
"""Regression tests for the public install and restore scripts.

Every case uses a newly-created HOME.  The real ``dig`` child is directed to
an unused local UDP/TCP port, so the test never relies on public DNS or the
machine owner's account state.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL = REPO_ROOT / "scripts" / "install.sh"
RESTORE = REPO_ROOT / "scripts" / "restore.sh"
MARKER = "_zcode-verify= zcode-verify-a3f8d92e6b1c"
OWNER_TEXT = "stateful-dig-wrapper:any-query:v2\n"
ROOT: Path | None = None


def fail(message: str) -> None:
    raise AssertionError(message)


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def command_text(args: Iterable[object]) -> str:
    return " ".join(str(item) for item in args)


def run(
    args: Iterable[object],
    home: Path,
    *,
    allowed: Tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    """Run one child with an isolated HOME and useful diagnostics."""
    assert ROOT is not None
    child_env: Dict[str, str] = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": str(ROOT / "tmp"),
        "LC_ALL": "C",
    }
    rendered = [str(item) for item in args]
    result = subprocess.run(
        rendered,
        cwd=REPO_ROOT,
        env=child_env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode not in allowed:
        fail(
            "unexpected exit status {} for {}\nstdout:\n{}\nstderr:\n{}".format(
                result.returncode, command_text(rendered), result.stdout, result.stderr
            )
        )
    return result


def paths(home: Path) -> Tuple[Path, Path, Path, Path]:
    target = home / ".local" / "bin" / "dig"
    state = home / ".cache" / "dig-zcode-wrapper"
    backup_root = home / ".local" / "share" / "stateful-dig-wrapper" / "backups"
    latest = home / ".local" / "share" / "stateful-dig-wrapper" / "LAST_BACKUP"
    return target, state, backup_root, latest


def last_backup(home: Path) -> Path:
    _, _, backup_root, latest = paths(home)
    assert_true(latest.is_file() and not latest.is_symlink(), "LAST_BACKUP was not created")
    location = Path(latest.read_text(encoding="utf-8").strip())
    assert_true(location.is_dir() and not location.is_symlink(), "backup directory is missing")
    assert_true(location.parent == backup_root, "backup escaped its managed backup root")
    return location


def query_args(name: str) -> Tuple[str, ...]:
    # Port 9 on localhost avoids public DNS and bounds any timeout.
    return (name, "@127.0.0.1", "-p", "9", "+time=1", "+tries=1")


def run_installed_dig(home: Path, name: str) -> subprocess.CompletedProcess[str]:
    target, _, _, _ = paths(home)
    # dig returns 9 on an unreachable local resolver; the wrapper intentionally
    # preserves that code while still recording a syntactically valid query.
    return run((target, *query_args(name)), home, allowed=(0, 9))


def write_file(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def snapshot_tree(root: Path) -> Dict[str, Tuple[str, int, bytes | str | None]]:
    """Capture content, file type, and permission bits without following links."""
    assert_true(root.is_dir() and not root.is_symlink(), f"not a real directory: {root}")
    snapshot: Dict[str, Tuple[str, int, bytes | str | None]] = {
        ".": ("dir", stat.S_IMODE(root.lstat().st_mode), None)
    }
    for path in sorted(root.rglob("*"), key=lambda candidate: str(candidate.relative_to(root))):
        info = path.lstat()
        relative = str(path.relative_to(root))
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            snapshot[relative] = ("dir", mode, None)
        elif stat.S_ISREG(info.st_mode):
            snapshot[relative] = ("file", mode, path.read_bytes())
        elif stat.S_ISLNK(info.st_mode):
            snapshot[relative] = ("symlink", mode, os.readlink(path))
        else:
            fail(f"unexpected filesystem type in state snapshot: {path}")
    return snapshot


def create_valid_state(state: Path) -> Dict[str, Tuple[str, int, bytes | str | None]]:
    state.mkdir(mode=0o700, parents=True)
    state.chmod(0o700)
    write_file(state / ".owner", OWNER_TEXT.encode("utf-8"), 0o600)
    payload = {"version": 2, "counts": {"preexisting-state.example": 7}}
    write_file(
        state / "state.json",
        (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        0o600,
    )
    write_file(state / ".state.lock", b"", 0o600)
    return snapshot_tree(state)


def new_home(name: str) -> Path:
    assert ROOT is not None
    home = ROOT / "homes" / name
    home.mkdir(mode=0o700, parents=True)
    return home


def test_clean_install_second_marker_and_restore() -> None:
    home = new_home("clean")
    target, state, _, _ = paths(home)

    run(("/bin/sh", INSTALL), home)
    backup = last_backup(home)
    assert_true(target.is_file() and not target.is_symlink(), "clean install did not publish a regular wrapper")
    assert_true((backup / "target.status").read_text(encoding="utf-8").strip() == "missing", "clean target status is wrong")
    assert_true((backup / "state.status").read_text(encoding="utf-8").strip() == "missing", "clean state status is wrong")

    first = run_installed_dig(home, "clean-install.example")
    second = run_installed_dig(home, "clean-install.example")
    assert_true(MARKER not in first.stdout, "first lookup unexpectedly added the marker")
    assert_true(second.stdout.count(MARKER) == 1, "second lookup did not add exactly one marker")
    assert_true((state / "state.json").is_file(), "installed wrapper did not create state")

    run(("/bin/sh", RESTORE), home)
    assert_true(not target.exists() and not target.is_symlink(), "clean restore did not remove installed wrapper")
    assert_true(not state.exists() and not state.is_symlink(), "clean restore did not remove newly-created state")


def test_regular_target_and_valid_state_are_restored() -> None:
    home = new_home("regular")
    target, state, _, _ = paths(home)
    original_target = b"#!/bin/sh\nprintf '%s\\n' original-dig\n"
    write_file(target, original_target, 0o751)
    original_mode = stat.S_IMODE(target.lstat().st_mode)
    original_state = create_valid_state(state)

    run(("/bin/sh", INSTALL), home)
    assert_true(target.is_file() and target.read_bytes() != original_target, "install did not replace regular target")
    mutation = run_installed_dig(home, "state-mutation.example")
    assert_true(mutation.returncode in {0, 9}, "wrapper mutation query did not run")
    assert_true(snapshot_tree(state) != original_state, "post-install state did not diverge from saved state")

    run(("/bin/sh", RESTORE), home)
    assert_true(target.is_file() and not target.is_symlink(), "regular target was not restored as a regular file")
    assert_true(target.read_bytes() == original_target, "regular target content was not restored")
    assert_true(stat.S_IMODE(target.lstat().st_mode) == original_mode, "regular target mode was not restored")
    assert_true(snapshot_tree(state) == original_state, "valid pre-install state was not restored exactly")


def test_symlink_target_is_restored_as_a_symlink() -> None:
    home = new_home("symlink")
    target, _, _, _ = paths(home)
    original = home / "original-dig"
    write_file(original, b"#!/bin/sh\nprintf '%s\\n' symlink-origin\n", 0o755)
    target.parent.mkdir(mode=0o700, parents=True)
    link_value = "../../original-dig"
    target.symlink_to(link_value)

    run(("/bin/sh", INSTALL), home)
    assert_true(target.is_file() and not target.is_symlink(), "install did not replace symlink with wrapper")
    run(("/bin/sh", RESTORE), home)
    assert_true(target.is_symlink(), "symlink target was not restored as a symlink")
    assert_true(os.readlink(target) == link_value, "symlink target text was not restored exactly")
    assert_true(target.resolve() == original.resolve(), "restored symlink no longer resolves to the original target")


def test_fifo_is_rejected_before_installation() -> None:
    home = new_home("fifo")
    target, _, backup_root, latest = paths(home)
    target.parent.mkdir(mode=0o700, parents=True)
    os.mkfifo(target, 0o600)

    result = run(("/bin/sh", INSTALL), home, allowed=tuple(range(1, 256)))
    assert_true("must be a regular file or symlink" in result.stderr, "FIFO rejection did not explain the refusal")
    assert_true(stat.S_ISFIFO(target.lstat().st_mode), "FIFO was replaced despite install refusal")
    assert_true(not latest.exists() and not latest.is_symlink(), "rejected FIFO unexpectedly created LAST_BACKUP")
    assert_true(not backup_root.exists() and not backup_root.is_symlink(), "rejected FIFO unexpectedly created a backup")


def test_target_symlink_to_directory_is_rejected_without_mutation() -> None:
    home = new_home("target-symlink-directory")
    target, state, backup_root, latest = paths(home)
    original_state = create_valid_state(state)
    referent = home / "target-directory-referent"
    referent.mkdir(mode=0o700)
    write_file(referent / "sentinel", b"target-directory-sentinel\n", 0o600)
    original_referent = snapshot_tree(referent)
    target.parent.mkdir(mode=0o700, parents=True)
    link_value = "../../target-directory-referent"
    target.symlink_to(link_value)

    result = run(("/bin/sh", INSTALL), home, allowed=tuple(range(1, 256)))
    assert_true(
        "must not be a symlink to a directory" in result.stderr,
        "target symlink-to-directory rejection did not explain the refusal",
    )
    assert_true(target.is_symlink(), "rejected target symlink was replaced")
    assert_true(os.readlink(target) == link_value, "rejected target symlink text changed")
    assert_true(snapshot_tree(referent) == original_referent, "target directory referent was mutated")
    assert_true(snapshot_tree(state) == original_state, "target rejection mutated preexisting state")
    assert_true(not latest.exists() and not latest.is_symlink(), "target rejection created LAST_BACKUP")
    assert_true(not backup_root.exists() and not backup_root.is_symlink(), "target rejection created a backup")


def test_last_backup_directory_is_rejected_without_mutation() -> None:
    home = new_home("last-backup-directory")
    target, state, backup_root, latest = paths(home)
    original_target = b"#!/bin/sh\nprintf '%s\\n' original-before-pointer-directory\n"
    write_file(target, original_target, 0o755)
    original_state = create_valid_state(state)
    latest.mkdir(mode=0o700, parents=True)
    write_file(latest / "sentinel", b"last-backup-directory-sentinel\n", 0o600)
    original_latest = snapshot_tree(latest)

    result = run(("/bin/sh", INSTALL), home, allowed=tuple(range(1, 256)))
    assert_true(
        "must not be a directory or symlink to a directory" in result.stderr,
        "LAST_BACKUP directory rejection did not explain the refusal",
    )
    assert_true(target.read_bytes() == original_target, "LAST_BACKUP directory rejection changed target")
    assert_true(snapshot_tree(state) == original_state, "LAST_BACKUP directory rejection changed state")
    assert_true(snapshot_tree(latest) == original_latest, "LAST_BACKUP directory was mutated")
    assert_true(not backup_root.exists() and not backup_root.is_symlink(), "LAST_BACKUP directory rejection created a backup")


def test_last_backup_symlink_to_directory_is_rejected_without_mutation() -> None:
    home = new_home("last-backup-symlink-directory")
    target, state, backup_root, latest = paths(home)
    original_target = b"#!/bin/sh\nprintf '%s\\n' original-before-pointer-symlink\n"
    write_file(target, original_target, 0o755)
    original_state = create_valid_state(state)
    referent = home / "last-backup-directory-referent"
    referent.mkdir(mode=0o700)
    write_file(referent / "sentinel", b"last-backup-symlink-sentinel\n", 0o600)
    original_referent = snapshot_tree(referent)
    latest.parent.mkdir(mode=0o700, parents=True)
    link_value = "../../../last-backup-directory-referent"
    latest.symlink_to(link_value)

    result = run(("/bin/sh", INSTALL), home, allowed=tuple(range(1, 256)))
    assert_true(
        "must not be a directory or symlink to a directory" in result.stderr,
        "LAST_BACKUP symlink-to-directory rejection did not explain the refusal",
    )
    assert_true(target.read_bytes() == original_target, "LAST_BACKUP symlink rejection changed target")
    assert_true(snapshot_tree(state) == original_state, "LAST_BACKUP symlink rejection changed state")
    assert_true(latest.is_symlink(), "LAST_BACKUP symlink was replaced")
    assert_true(os.readlink(latest) == link_value, "LAST_BACKUP symlink text changed")
    assert_true(snapshot_tree(referent) == original_referent, "LAST_BACKUP referent was mutated")
    assert_true(not backup_root.exists() and not backup_root.is_symlink(), "LAST_BACKUP symlink rejection created a backup")


def test_unrestorable_state_is_rejected_before_target_mutation() -> None:
    home = new_home("state-symlink")
    target, state, _, latest = paths(home)
    original_target = b"#!/bin/sh\nprintf '%s\\n' original-before-unsafe-state\n"
    write_file(target, original_target, 0o755)
    _ = create_valid_state(state)
    (state / "unexpected-link").symlink_to("state.json")

    result = run(("/bin/sh", INSTALL), home, allowed=tuple(range(1, 256)))
    assert_true("archive validation failed" in result.stderr, "unsafe state did not fail archive validation")
    assert_true(target.is_file() and not target.is_symlink(), "unsafe state changed target type")
    assert_true(target.read_bytes() == original_target, "unsafe state replaced the existing target")
    assert_true(not latest.exists() and not latest.is_symlink(), "unsafe state unexpectedly published LAST_BACKUP")


def test_tampered_installed_target_fails_closed_on_restore() -> None:
    home = new_home("tamper")
    target, _, _, _ = paths(home)
    run(("/bin/sh", INSTALL), home)
    _ = last_backup(home)
    tampered = b"#!/bin/sh\nprintf '%s\\n' changed-after-install\n"
    write_file(target, tampered, 0o755)

    result = run(("/bin/sh", RESTORE), home, allowed=tuple(range(1, 256)))
    assert_true("was modified after installation" in result.stderr, "tampered target did not fail closed")
    assert_true(target.is_file() and not target.is_symlink(), "failed restore changed target type")
    assert_true(target.read_bytes() == tampered, "failed restore overwrote the tampered target")


def main() -> int:
    global ROOT
    for required in (INSTALL, RESTORE, Path("/usr/bin/dig"), Path("/usr/bin/python3")):
        assert_true(required.is_file(), f"required file is missing: {required}")

    ROOT = Path(tempfile.mkdtemp(prefix="stateful-dig-wrapper-install-restore-"))
    (ROOT / "tmp").mkdir(mode=0o700)
    try:
        test_clean_install_second_marker_and_restore()
        test_regular_target_and_valid_state_are_restored()
        test_symlink_target_is_restored_as_a_symlink()
        test_fifo_is_rejected_before_installation()
        test_target_symlink_to_directory_is_rejected_without_mutation()
        test_last_backup_directory_is_rejected_without_mutation()
        test_last_backup_symlink_to_directory_is_rejected_without_mutation()
        test_unrestorable_state_is_rejected_before_target_mutation()
        test_tampered_installed_target_fails_closed_on_restore()
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
        ROOT = None

    print("PASS: install/restore regression tests")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
