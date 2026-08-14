#!/bin/sh
# Restore the target and state captured by scripts/install.sh.
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
COPYFILE_DISABLE=1
export COPYFILE_DISABLE
umask 077

die() {
    printf 'restore: %s\n' "$*" >&2
    exit 1
}

sha256_file() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

read_one_line() {
    [ -f "$1" ] && [ ! -L "$1" ] || die "missing regular metadata file: $1"
    value=$(/usr/bin/awk '
        NR == 1 { value = $0 }
        NR > 1 { exit 2 }
        END {
            if (NR != 1) exit 3
            printf "%s", value
        }
    ' "$1") || die "metadata must contain exactly one line: $1"
    printf '%s' "$value"
}

validate_sha() {
    case "$1" in
        ''|*[!0-9a-f]*) return 1 ;;
    esac
    [ "${#1}" -eq 64 ]
}

validate_archive_hash() {
    archive=$1
    digest_file=$2
    [ -f "$archive" ] && [ ! -L "$archive" ] || die "missing archive: $archive"
    expected=$(read_one_line "$digest_file")
    validate_sha "$expected" || die "invalid checksum metadata: $digest_file"
    actual=$(sha256_file "$archive")
    [ "$actual" = "$expected" ] || die "archive checksum mismatch: $archive"
}

case $# in
    0|1) ;;
    *) die 'usage: ./scripts/restore.sh [backup-directory]' ;;
esac

case ${HOME:-} in
    ''|/) die 'HOME must name a normal user home directory' ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ARCHIVE_VALIDATOR=$SCRIPT_DIR/validate_archive.py
TARGET_DIR=$HOME/.local/bin
TARGET=$TARGET_DIR/dig
CACHE_PARENT=$HOME/.cache
STATE_DIR=$CACHE_PARENT/dig-zcode-wrapper
SHARE_ROOT=$HOME/.local/share/stateful-dig-wrapper
BACKUP_ROOT=$SHARE_ROOT/backups
LAST_BACKUP=$SHARE_ROOT/LAST_BACKUP

[ -x /usr/bin/python3 ] || die '/usr/bin/python3 is missing or not executable'
[ -f "$ARCHIVE_VALIDATOR" ] && [ ! -L "$ARCHIVE_VALIDATOR" ] || \
    die 'scripts/validate_archive.py must be a regular file'
[ -d "$BACKUP_ROOT" ] && [ ! -L "$BACKUP_ROOT" ] || die "missing backup root: $BACKUP_ROOT"

if [ "$#" -eq 1 ]; then
    REQUESTED_BACKUP=$1
else
    REQUESTED_BACKUP=$(read_one_line "$LAST_BACKUP")
fi
[ -d "$REQUESTED_BACKUP" ] && [ ! -L "$REQUESTED_BACKUP" ] || \
    die "backup is not a real directory: $REQUESTED_BACKUP"

BACKUP_ROOT_REAL=$(CDPATH= cd -- "$BACKUP_ROOT" && pwd -P)
BACKUP_DIR=$(CDPATH= cd -- "$REQUESTED_BACKUP" && pwd -P)
case "$BACKUP_DIR" in
    "$BACKUP_ROOT_REAL"/*) ;;
    *) die 'backup directory must be inside the managed backup root' ;;
esac

STATUS=$(read_one_line "$BACKUP_DIR/status")
case "$STATUS" in
    PREPARED|INSTALLED) ;;
    *) die "unsupported backup status: $STATUS" ;;
esac

TARGET_STATUS=$(read_one_line "$BACKUP_DIR/target.status")
STATE_STATUS=$(read_one_line "$BACKUP_DIR/state.status")
CACHE_PARENT_STATUS=$(read_one_line "$BACKUP_DIR/cache-parent.status")
case "$TARGET_STATUS" in present|missing) ;; *) die 'invalid target.status' ;; esac
case "$STATE_STATUS" in present|missing) ;; *) die 'invalid state.status' ;; esac
case "$CACHE_PARENT_STATUS" in present|missing) ;; *) die 'invalid cache-parent.status' ;; esac

WRAPPER_SHA=$(read_one_line "$BACKUP_DIR/wrapper.sha256")
validate_sha "$WRAPPER_SHA" || die 'invalid wrapper.sha256'

if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    [ -f "$TARGET" ] && [ ! -L "$TARGET" ] || \
        die "$TARGET is not the installed regular wrapper; refusing to overwrite it"
    CURRENT_SHA=$(sha256_file "$TARGET")
    [ "$CURRENT_SHA" = "$WRAPPER_SHA" ] || \
        die "$TARGET was modified after installation; refusing to overwrite it"
fi

if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || \
        die "$STATE_DIR is not a real directory; refusing to move it"
fi

TARGET_STAGE=
STATE_STAGE=
cleanup() {
    case "$TARGET_STAGE" in
        "$TARGET_DIR"/.stateful-dig-target.*)
            [ ! -e "$TARGET_STAGE" ] || /bin/rm -rf -- "$TARGET_STAGE"
            ;;
    esac
    case "$STATE_STAGE" in
        "$CACHE_PARENT"/.stateful-dig-state.*)
            [ ! -e "$STATE_STAGE" ] || /bin/rm -rf -- "$STATE_STAGE"
            ;;
    esac
}
trap cleanup 0 1 2 15

/bin/mkdir -p "$TARGET_DIR" "$CACHE_PARENT"

if [ "$TARGET_STATUS" = present ]; then
    validate_archive_hash "$BACKUP_DIR/target.before.tar" \
        "$BACKUP_DIR/target.before.tar.sha256"
    /usr/bin/python3 "$ARCHIVE_VALIDATOR" target "$BACKUP_DIR/target.before.tar"
    TARGET_STAGE=$(/usr/bin/mktemp -d "$TARGET_DIR/.stateful-dig-target.XXXXXX")
    /usr/bin/tar -xpf "$BACKUP_DIR/target.before.tar" -C "$TARGET_STAGE"
    [ -e "$TARGET_STAGE/dig" ] || [ -L "$TARGET_STAGE/dig" ] || \
        die 'target archive did not extract a dig entry'
fi

if [ "$STATE_STATUS" = present ]; then
    validate_archive_hash "$BACKUP_DIR/state.before.tar" \
        "$BACKUP_DIR/state.before.tar.sha256"
    /usr/bin/python3 "$ARCHIVE_VALIDATOR" state "$BACKUP_DIR/state.before.tar"
    STATE_STAGE=$(/usr/bin/mktemp -d "$CACHE_PARENT/.stateful-dig-state.XXXXXX")
    /usr/bin/tar -xpf "$BACKUP_DIR/state.before.tar" -C "$STATE_STAGE"
    [ -d "$STATE_STAGE/dig-zcode-wrapper" ] && \
        [ ! -L "$STATE_STAGE/dig-zcode-wrapper" ] || \
        die 'state archive did not extract the expected directory'
fi

STAMP=$(/bin/date -u '+%Y%m%dT%H%M%SZ')
SNAPSHOT_ROOT=$SHARE_ROOT/restore-snapshots
SNAPSHOT_DIR=$SNAPSHOT_ROOT/$STAMP-$$
/bin/mkdir -p "$SNAPSHOT_ROOT"
[ -d "$SNAPSHOT_ROOT" ] && [ ! -L "$SNAPSHOT_ROOT" ] || \
    die "$SNAPSHOT_ROOT must be a real directory"
/bin/chmod 700 "$SNAPSHOT_ROOT"

if [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ]; then
    /bin/mkdir -m 700 "$SNAPSHOT_DIR"
    /bin/mv "$STATE_DIR" "$SNAPSHOT_DIR/state.after-install"
fi

if [ "$STATE_STATUS" = present ]; then
    /bin/mv "$STATE_STAGE/dig-zcode-wrapper" "$STATE_DIR"
fi

if [ "$TARGET_STATUS" = present ]; then
    /bin/mv -f "$TARGET_STAGE/dig" "$TARGET"
else
    if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
        /bin/rm -f -- "$TARGET"
    fi
fi

if [ "$CACHE_PARENT_STATUS" = missing ] && [ ! -e "$STATE_DIR" ]; then
    /bin/rmdir "$CACHE_PARENT" 2>/dev/null || true
fi

printf 'Restored from: %s\n' "$BACKUP_DIR"
if [ -d "$SNAPSHOT_DIR/state.after-install" ]; then
    printf 'Preserved post-install state: %s\n' "$SNAPSHOT_DIR/state.after-install"
fi
printf 'System dig remains: /usr/bin/dig\n'
