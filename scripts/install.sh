#!/bin/sh
# Install the wrapper into the current user's PATH without modifying /usr/bin/dig.
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
# Prevent macOS tar from adding hidden AppleDouble (._*) archive members that
# would make the strict restore validator reject an otherwise normal backup.
COPYFILE_DISABLE=1
export COPYFILE_DISABLE
umask 077

die() {
    printf 'install: %s\n' "$*" >&2
    exit 1
}

sha256_file() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
SOURCE=$REPO_ROOT/src/dig_wrapper.py
ARCHIVE_VALIDATOR=$SCRIPT_DIR/validate_archive.py

case ${HOME:-} in
    ''|/) die 'HOME must name a normal user home directory' ;;
esac

REAL_DIG=/usr/bin/dig
PYTHON=/usr/bin/python3
TARGET_DIR=$HOME/.local/bin
TARGET=$TARGET_DIR/dig
CACHE_PARENT=$HOME/.cache
STATE_DIR=$CACHE_PARENT/dig-zcode-wrapper
SHARE_ROOT=$HOME/.local/share/stateful-dig-wrapper
BACKUP_ROOT=$SHARE_ROOT/backups
LAST_BACKUP=$SHARE_ROOT/LAST_BACKUP

[ -x "$REAL_DIG" ] || die '/usr/bin/dig is missing or not executable'
[ -x "$PYTHON" ] || die '/usr/bin/python3 is missing or not executable'
[ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || die 'src/dig_wrapper.py must be a regular file'
[ -f "$ARCHIVE_VALIDATOR" ] && [ ! -L "$ARCHIVE_VALIDATOR" ] || \
    die 'scripts/validate_archive.py must be a regular file'

# BSD mv treats an existing directory operand as a destination directory.  Do
# these checks before creating backup directories or touching target/state so
# neither a directory nor a symlink-to-directory can redirect installation.
if [ -d "$LAST_BACKUP" ]; then
    die "$LAST_BACKUP must not be a directory or symlink to a directory"
fi

if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    if [ -L "$TARGET" ]; then
        [ ! -d "$TARGET" ] || \
            die "$TARGET must not be a symlink to a directory"
        : # Symlinks are archived and restored as symlinks, without dereferencing.
    elif [ -f "$TARGET" ]; then
        :
    else
        die "$TARGET must be a regular file or symlink; refusing to replace it"
    fi
fi
if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || \
        die "$STATE_DIR must be a real directory before it can be backed up"
fi

CACHE_PARENT_STATUS=present
if [ ! -d "$CACHE_PARENT" ]; then
    [ ! -e "$CACHE_PARENT" ] && [ ! -L "$CACHE_PARENT" ] || \
        die "$CACHE_PARENT exists but is not a directory"
    CACHE_PARENT_STATUS=missing
fi

/bin/mkdir -p "$TARGET_DIR" "$BACKUP_ROOT" "$CACHE_PARENT"
[ -d "$BACKUP_ROOT" ] && [ ! -L "$BACKUP_ROOT" ] || \
    die "$BACKUP_ROOT must be a real directory"
/bin/chmod 700 "$BACKUP_ROOT"
if [ "$CACHE_PARENT_STATUS" = missing ]; then
    /bin/chmod 700 "$CACHE_PARENT"
fi

STAMP=$(/bin/date -u '+%Y%m%dT%H%M%SZ')
BACKUP_DIR=$BACKUP_ROOT/$STAMP-$$
[ ! -e "$BACKUP_DIR" ] || die "backup already exists: $BACKUP_DIR"
/bin/mkdir -m 700 "$BACKUP_DIR"

printf '%s\n' "$CACHE_PARENT_STATUS" > "$BACKUP_DIR/cache-parent.status"

if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    printf '%s\n' present > "$BACKUP_DIR/target.status"
    (CDPATH= cd -- "$TARGET_DIR" && /usr/bin/tar -cpf "$BACKUP_DIR/target.before.tar" dig)
    sha256_file "$BACKUP_DIR/target.before.tar" > "$BACKUP_DIR/target.before.tar.sha256"
    "$PYTHON" "$ARCHIVE_VALIDATOR" target "$BACKUP_DIR/target.before.tar"
else
    printf '%s\n' missing > "$BACKUP_DIR/target.status"
fi

if [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ]; then
    printf '%s\n' present > "$BACKUP_DIR/state.status"
    (CDPATH= cd -- "$CACHE_PARENT" && \
        /usr/bin/tar -cpf "$BACKUP_DIR/state.before.tar" dig-zcode-wrapper)
    sha256_file "$BACKUP_DIR/state.before.tar" > "$BACKUP_DIR/state.before.tar.sha256"
    "$PYTHON" "$ARCHIVE_VALIDATOR" state "$BACKUP_DIR/state.before.tar"
else
    printf '%s\n' missing > "$BACKUP_DIR/state.status"
fi

WRAPPER_SHA=$(sha256_file "$SOURCE")
printf '%s\n' "$WRAPPER_SHA" > "$BACKUP_DIR/wrapper.sha256"
/usr/bin/shasum -a 256 "$REAL_DIG" > "$BACKUP_DIR/system-dig.sha256"
/usr/bin/codesign -dv --verbose=4 "$REAL_DIG" \
    > "$BACKUP_DIR/system-dig.codesign.txt" 2>&1 || \
    die 'Apple code-signature inspection failed; installation was not attempted'

cat > "$BACKUP_DIR/manifest.txt" <<EOF
format=1
created_utc=$STAMP
target=$TARGET
state=$STATE_DIR
wrapper_sha256=$WRAPPER_SHA
system_dig=$REAL_DIG
EOF
printf '%s\n' PREPARED > "$BACKUP_DIR/status"

POINTER_TMP=
INSTALL_TMP=
cleanup() {
    if [ -n "$POINTER_TMP" ] && [ -e "$POINTER_TMP" ]; then
        /bin/rm -f -- "$POINTER_TMP"
    fi
    if [ -n "$INSTALL_TMP" ] && [ -e "$INSTALL_TMP" ]; then
        /bin/rm -f -- "$INSTALL_TMP"
    fi
}
trap cleanup 0 1 2 15

# Publish the recovery pointer before the first mutation.
POINTER_TMP=$(/usr/bin/mktemp "$SHARE_ROOT/.LAST_BACKUP.XXXXXX")
printf '%s\n' "$BACKUP_DIR" > "$POINTER_TMP"
/bin/chmod 600 "$POINTER_TMP"
"$PYTHON" - "$POINTER_TMP" "$LAST_BACKUP" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
POINTER_TMP=

INSTALL_TMP=$(/usr/bin/mktemp "$TARGET_DIR/.dig.install.XXXXXX")
/usr/bin/install -m 0755 "$SOURCE" "$INSTALL_TMP"
[ "$(sha256_file "$INSTALL_TMP")" = "$WRAPPER_SHA" ] || \
    die 'installed temporary file failed its checksum check'
"$PYTHON" - "$INSTALL_TMP" "$TARGET" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
INSTALL_TMP=
printf '%s\n' INSTALLED > "$BACKUP_DIR/status"

printf 'Installed: %s\n' "$TARGET"
printf 'Backup:   %s\n' "$BACKUP_DIR"
printf 'Next:      export PATH="$HOME/.local/bin:$PATH"\n'
