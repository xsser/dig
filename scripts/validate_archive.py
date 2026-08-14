#!/usr/bin/python3
"""Validate install/restore tar members before any archive is extracted."""

from __future__ import annotations

import sys
import tarfile
from pathlib import PurePosixPath
from typing import Iterable, Tuple


def fail(message: str) -> None:
    raise ValueError(message)


def safe_parts(name: str) -> Tuple[str, ...]:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        fail("archive contains an unsafe path")
    return tuple(part for part in path.parts if part not in {"", "."})


def validate_target(members: Iterable[tarfile.TarInfo]) -> None:
    items = list(members)
    if len(items) != 1 or safe_parts(items[0].name) != ("dig",):
        fail("target archive must contain exactly one dig entry")
    if not (items[0].isfile() or items[0].issym()):
        fail("target archive entry must be a regular file or symlink")


def validate_state(members: Iterable[tarfile.TarInfo]) -> None:
    items = list(members)
    if not items:
        fail("state archive is empty")
    for member in items:
        parts = safe_parts(member.name)
        if not parts or parts[0] != "dig-zcode-wrapper":
            fail("state archive escaped its expected root")
        if not (member.isdir() or member.isfile()):
            fail("state archive accepts only directories and regular files")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"target", "state"}:
        print("usage: validate_archive.py {target|state} ARCHIVE", file=sys.stderr)
        return 2
    try:
        with tarfile.open(sys.argv[2], "r") as archive:
            members = archive.getmembers()
        if sys.argv[1] == "target":
            validate_target(members)
        else:
            validate_state(members)
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"archive validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
