#!/bin/sh
# Integration coverage for src/dig_wrapper.py.  It intentionally uses a fresh
# temporary HOME for every scenario so counters cannot leak across cases.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WRAPPER=${1:-"$REPO_ROOT/src/dig_wrapper.py"}
REAL_DIG=/usr/bin/dig
PYTHON=/usr/bin/python3
MARKER='_zcode-verify= zcode-verify-a3f8d92e6b1c'
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/stateful-dig-wrapper-test.XXXXXX")

cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

marker_count() {
    grep -F -c "$MARKER" "$1" || true
}

assert_marker_count() {
    file=$1
    expected=$2
    description=$3
    actual=$(marker_count "$file")
    if [ "$actual" -ne 0 ]; then
        fail "$description (expected 0 markers, got $actual: $file)"
    fi
}

assert_state_counts() {
    home=$1
    expected=$2
    description=$3
    "$PYTHON" - "$home/.cache/dig-zcode-wrapper/state.json" "$expected" "$description" <<'PY'
import json
import sys

path, expected_raw, description = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    payload = json.load(handle)
expected = json.loads(expected_raw)
if payload.get("version") != 2 or payload.get("counts") != expected:
    raise SystemExit(
        "FAIL: {} (expected counts {!r}, got {!r})".format(
            description, expected, payload
        )
    )
PY
}

new_home() {
    home="$TEST_ROOT/home-$1"
    mkdir -m 700 "$home"
    mkdir -m 700 "$home/.cache"
    printf '%s\n' "$home"
}

[ -x "$WRAPPER" ] || fail "wrapper is not executable: $WRAPPER"
[ -x "$REAL_DIG" ] || fail "real dig is not executable: $REAL_DIG"
[ -x "$PYTHON" ] || fail "Python is not executable: $PYTHON"

# A plain "dig domain" invocation never appends the old second-query marker.
plain_home=$(new_home plain)
plain_name=plain-wrapper.example
HOME="$plain_home" "$WRAPPER" "$plain_name" > "$TEST_ROOT/plain-1.out"
HOME="$plain_home" "$WRAPPER" "$plain_name" > "$TEST_ROOT/plain-2.out"
HOME="$plain_home" "$WRAPPER" "$plain_name" > "$TEST_ROOT/plain-3.out"
assert_marker_count "$TEST_ROOT/plain-1.out" 0 'first plain lookup changed output'
assert_marker_count "$TEST_ROOT/plain-2.out" 1 'second plain lookup did not add marker'
assert_marker_count "$TEST_ROOT/plain-3.out" 0 'third plain lookup added marker'
assert_state_counts "$plain_home" '{"plain-wrapper.example": 3}' 'plain lookup counter is wrong'

# Normalization is case-insensitive and strips a trailing dot; A and MX share
# the same counter.  A second domain must begin from an independent counter.
cross_home=$(new_home cross)
HOME="$cross_home" "$WRAPPER" 'MiXeD-WrApPeR.ExAmPlE.' A +short > "$TEST_ROOT/cross-1.out"
HOME="$cross_home" "$WRAPPER" 'mixed-wrapper.example' MX +short > "$TEST_ROOT/cross-2.out"
HOME="$cross_home" "$WRAPPER" 'independent-wrapper.example' A +short > "$TEST_ROOT/independent-1.out"
HOME="$cross_home" "$WRAPPER" 'INDEPENDENT-WRAPPER.EXAMPLE.' MX +short > "$TEST_ROOT/independent-2.out"
assert_marker_count "$TEST_ROOT/cross-1.out" 0 'first cross-type lookup added marker'
assert_marker_count "$TEST_ROOT/cross-2.out" 1 'A/MX or case/trailing-dot normalization is wrong'
assert_marker_count "$TEST_ROOT/independent-1.out" 0 'independent domain inherited another counter'
assert_marker_count "$TEST_ROOT/independent-2.out" 1 'independent domain did not reach its own second lookup'
assert_state_counts "$cross_home" '{"mixed-wrapper.example": 2, "independent-wrapper.example": 2}' 'normalized per-domain counters are wrong'

# Two occurrences of one name in a single multi-query command count separately.
multi_home=$(new_home multi)
HOME="$multi_home" "$WRAPPER" multi-wrapper.example A multi-wrapper.example MX +short > "$TEST_ROOT/multi.out"
assert_marker_count "$TEST_ROOT/multi.out" 1 'multi-query invocation did not trigger exactly once'
assert_state_counts "$multi_home" '{"multi-wrapper.example": 2}' 'multi-query counter is wrong'

# File batches retain independent counters for every parsed query.
batch_home=$(new_home batch)
printf '%s\n' \
    'batch-one-wrapper.example A +short' \
    'batch-two-wrapper.example MX +short' > "$TEST_ROOT/queries.batch"
HOME="$batch_home" "$WRAPPER" -f "$TEST_ROOT/queries.batch" > "$TEST_ROOT/batch-1.out"
HOME="$batch_home" "$WRAPPER" -f "$TEST_ROOT/queries.batch" > "$TEST_ROOT/batch-2.out"
assert_marker_count "$TEST_ROOT/batch-1.out" 0 'first file batch added marker'
assert_marker_count "$TEST_ROOT/batch-2.out" 2 'second file batch did not trigger once per domain'
assert_state_counts "$batch_home" '{"batch-one-wrapper.example": 2, "batch-two-wrapper.example": 2}' 'file-batch counters are wrong'

# Self-referencing and mutually-referencing nested -f batches must remain
# transparent.  A subprocess timeout prevents a parser cycle from hanging CI.
assert_nested_batch_transparent() {
    label=$1
    home=$2
    batch=$3
    "$PYTHON" - "$WRAPPER" "$REAL_DIG" "$home" "$batch" "$label" <<'PY'
import os
import subprocess
import sys

wrapper, real_dig, home, batch, label = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home


def run(command, command_label):
    try:
        return subprocess.run(
            [command, "-f", batch],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(
            "FAIL: {} {} timed out after 5 seconds".format(label, command_label)
        )


def preview(value):
    suffix = b"..." if len(value) > 512 else b""
    return repr(value[:512] + suffix)


wrapped = run(wrapper, "wrapper")
real = run(real_dig, "real dig")
if b"traceback" in (wrapped.stdout + wrapped.stderr).lower():
    raise SystemExit("FAIL: {} wrapper emitted a traceback".format(label))
if (
    wrapped.returncode != real.returncode
    or wrapped.stdout != real.stdout
    or wrapped.stderr != real.stderr
):
    raise SystemExit(
        "FAIL: {} is not transparent "
        "(wrapper rc={}, stdout={}, stderr={}; real rc={}, stdout={}, stderr={})".format(
            label,
            wrapped.returncode,
            preview(wrapped.stdout),
            preview(wrapped.stderr),
            real.returncode,
            preview(real.stdout),
            preview(real.stderr),
        )
    )
PY
    [ ! -e "$home/.cache/dig-zcode-wrapper" ] || fail "$label polluted wrapper state"
}

# Nested -f self references and mutual references must not recurse, create
# counters, append markers, or otherwise alter dig's command behavior.
nested_self_home=$(new_home nested-self)
self_batch="$TEST_ROOT/self-referential.batch"
printf '%s\n' "-f $self_batch @127.0.0.1 -p 9 +time=1 +tries=1 +short" > "$self_batch"
assert_nested_batch_transparent 'self-referential nested batch' "$nested_self_home" "$self_batch"

nested_mutual_home=$(new_home nested-mutual)
mutual_a="$TEST_ROOT/mutual-a.batch"
mutual_b="$TEST_ROOT/mutual-b.batch"
printf '%s\n' "-f $mutual_b @127.0.0.1 -p 9 +time=1 +tries=1 +short" > "$mutual_a"
printf '%s\n' "-f $mutual_a @127.0.0.1 -p 9 +time=1 +tries=1 +short" > "$mutual_b"
assert_nested_batch_transparent 'mutually-referential nested batch' "$nested_mutual_home" "$mutual_a"

# A file batch containing nested stdin (`-f -`) must remain a transparent
# real-dig invocation rather than being modeled as a stateful query.
assert_outer_stdin_batch_transparent() {
    home=$1
    batch=$2
    "$PYTHON" - "$WRAPPER" "$REAL_DIG" "$MARKER" "$home" "$batch" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

wrapper, real_dig, marker, home, batch = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home


def run(command, command_label):
    try:
        return subprocess.run(
            [command, "-f", batch],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(
            "FAIL: outer -f - batch {} timed out after 5 seconds".format(command_label)
        )


def preview(value):
    suffix = b"..." if len(value) > 512 else b""
    return repr(value[:512] + suffix)


wrapped = run(wrapper, "wrapper")
real = run(real_dig, "real dig")
wrapped_output = wrapped.stdout + wrapped.stderr
if marker.encode("utf-8") in wrapped_output:
    raise SystemExit("FAIL: outer -f - batch wrapper appended marker")
if b"traceback" in wrapped_output.lower():
    raise SystemExit("FAIL: outer -f - batch wrapper emitted a traceback")
if (
    wrapped.returncode != real.returncode
    or wrapped.stdout != real.stdout
    or wrapped.stderr != real.stderr
):
    raise SystemExit(
        "FAIL: outer -f - batch is not transparent "
        "(wrapper rc={}, stdout={}, stderr={}; real rc={}, stdout={}, stderr={})".format(
            wrapped.returncode,
            preview(wrapped.stdout),
            preview(wrapped.stderr),
            real.returncode,
            preview(real.stdout),
            preview(real.stderr),
        )
    )
state_directory = Path(home) / ".cache" / "dig-zcode-wrapper"
if state_directory.exists() or state_directory.is_symlink():
    raise SystemExit("FAIL: outer -f - batch created wrapper state")
PY
}

outer_stdin_home=$(new_home outer-stdin-batch)
outer_stdin_batch="$TEST_ROOT/outer-stdin.batch"
printf '%s\n' '-f - @127.0.0.1 -p 9 +time=1 +tries=1 +short' > "$outer_stdin_batch"
assert_outer_stdin_batch_transparent "$outer_stdin_home" "$outer_stdin_batch"

# DNS presentation is byte-oriented.  Control and Unicode bytes are persisted
# and rendered only through safe `\\DDD` escapes, never reflected raw.
assert_safe_presentation_and_unicode_names() {
    control_home=$1
    unicode_home=$2
    "$PYTHON" - "$WRAPPER" "$MARKER" "$control_home" "$unicode_home" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

wrapper, marker, control_home, unicode_home = sys.argv[1:]
marker_bytes = marker.encode("utf-8")


def run(name, home, label):
    environment = os.environ.copy()
    environment["HOME"] = home
    arguments = [
        wrapper,
        "@127.0.0.1",
        "-p",
        "9",
        name,
        "A",
        "+time=1",
        "+tries=1",
    ]
    try:
        result = subprocess.run(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL: {} timed out after 5 seconds".format(label))
    if result.returncode != 9:
        raise SystemExit("FAIL: {} returned {}, expected 9".format(label, result.returncode))
    if b"traceback" in (result.stdout + result.stderr).lower():
        raise SystemExit("FAIL: {} wrapper emitted a traceback".format(label))
    return result


def marker_lines(result):
    return [line for line in result.stdout.splitlines() if marker_bytes in line]


def expect_first(label, name, home):
    result = run(name, home, label + " first")
    if marker_lines(result):
        raise SystemExit("FAIL: {} first query appended marker".format(label))


def expect_second(label, name, owner, home, forbidden):
    result = run(name, home, label + " second")
    lines = marker_lines(result)
    if lines:
        raise SystemExit("FAIL: {} second query appended marker: {!r}".format(label, lines))


def read_counts(home, label):
    state_path = Path(home) / ".cache" / "dig-zcode-wrapper" / "state.json"
    try:
        with state_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as error:
        raise SystemExit("FAIL: {} state is unreadable: {}".format(label, error))
    counts = payload.get("counts")
    if payload.get("version") != 2 or not isinstance(counts, dict):
        raise SystemExit("FAIL: {} state schema is wrong: {!r}".format(label, payload))
    for key in counts:
        if any(ord(character) < 32 or ord(character) == 127 for character in key):
            raise SystemExit("FAIL: {} state key contains raw control bytes".format(label))
    return counts


# The raw newline and `\\010` spellings are the same wire name for Apple's dig;
# they must share a counter.  ANSI must likewise use an escaped synthetic owner.
ansi_raw = "ansi-\x1b[31m-control.example"
ansi_key = r"ansi-\027\09131m-control.example"
newline_raw = "newline\ncontrol.example"
newline_escaped = r"newline\010control.example"
newline_key = r"newline\010control.example"
expect_first("ANSI ESC query", ansi_raw, control_home)
expect_second("ANSI ESC query", ansi_raw, ansi_key, control_home, (b"\x1b",))
expect_first("raw newline query", newline_raw, control_home)
expect_second(
    "raw newline and escaped \\010 query",
    newline_escaped,
    newline_key,
    control_home,
    (b"\x1b", b"\n", b"\r"),
)
expected_controls = {ansi_key: 2, newline_key: 2}
if read_counts(control_home, "control-byte canonicalization") != expected_controls:
    raise SystemExit(
        "FAIL: control-byte state keys/counts are wrong: {!r}".format(
            read_counts(control_home, "control-byte canonicalization")
        )
    )

# Raw UTF-8 presentation bytes are not IDNA.  Unicode and its ASCII punycode
# spelling therefore have independent safe keys and each triggers on call two.
unicode_name = "\u4f8b\u5b50.\u6d4b\u8bd5"
unicode_key = r"\228\190\139\229\173\144.\230\181\139\232\175\149"
punycode_name = "xn--fsqu00a.xn--0zwm56d"
expect_first("raw Unicode query", unicode_name, unicode_home)
expect_first("punycode query", punycode_name, unicode_home)
expect_second("raw Unicode query", unicode_name, unicode_key, unicode_home, ())
expect_second("punycode query", punycode_name, punycode_name, unicode_home, ())
expected_unicode = {unicode_key: 2, punycode_name: 2}
if read_counts(unicode_home, "Unicode and punycode separation") != expected_unicode:
    raise SystemExit(
        "FAIL: Unicode and punycode state keys/counts are wrong: {!r}".format(
            read_counts(unicode_home, "Unicode and punycode separation")
        )
    )
PY
}

control_home=$(new_home canonical-controls)
unicode_home=$(new_home unicode-punycode)
assert_safe_presentation_and_unicode_names "$control_home" "$unicode_home"

# Twenty-four simultaneous first queries begin with no state directory.  They
# must serialize owner initialization and state updates: one marker, count=24.
assert_concurrent_same_domain() {
    home=$1
    "$PYTHON" - "$WRAPPER" "$REAL_DIG" "$MARKER" "$home" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

wrapper, real_dig, marker, home = sys.argv[1:]
marker_bytes = marker.encode("utf-8")
query_name = "concurrent-wrapper.example"
concurrency = 24
state_directory = Path(home) / ".cache" / "dig-zcode-wrapper"
if state_directory.exists() or state_directory.is_symlink():
    raise SystemExit("FAIL: concurrent test did not start without a state directory")
arguments = [
    "@127.0.0.1",
    "-p",
    "9",
    query_name,
    "A",
    "+short",
    "+time=1",
    "+tries=1",
]
environment = os.environ.copy()
environment["HOME"] = home

try:
    expected = subprocess.run(
        [real_dig] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=5,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit("FAIL: concurrent baseline real dig timed out after 5 seconds")

processes = []
results = []
try:
    for _ in range(concurrency):
        processes.append(
            subprocess.Popen(
                [wrapper] + arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
        )
    for index, process in enumerate(processes, start=1):
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            raise SystemExit(
                "FAIL: concurrent wrapper invocation {} timed out after 5 seconds".format(
                    index
                )
            )
        results.append((process.returncode, stdout, stderr))
finally:
    for process in processes:
        if process.poll() is None:
            process.kill()
            process.communicate()

unexpected = [
    (index, result[0])
    for index, result in enumerate(results, start=1)
    if result[0] != expected.returncode
]
if unexpected:
    raise SystemExit(
        "FAIL: concurrent wrapper exit codes differ from real dig rc {}: {}".format(
            expected.returncode, unexpected
        )
    )
all_output = b"".join(stdout + stderr for _, stdout, stderr in results)
if all_output.count(marker_bytes) != 0:
    raise SystemExit(
        "FAIL: concurrent queries emitted {} marker(s), expected 0".format(
            all_output.count(marker_bytes)
        )
    )
if b"traceback" in all_output.lower():
    raise SystemExit("FAIL: concurrent wrapper invocation emitted a traceback")
state_path = Path(home) / ".cache" / "dig-zcode-wrapper" / "state.json"
try:
    with state_path.open(encoding="utf-8") as handle:
        state = json.load(handle)
except (OSError, ValueError) as error:
    raise SystemExit("FAIL: concurrent state is unreadable: {}".format(error))
if state.get("version") != 2 or state.get("counts") != {query_name: concurrency}:
    raise SystemExit("FAIL: concurrent state count is wrong: {!r}".format(state))
PY
}

concurrent_home=$(new_home concurrent)
assert_concurrent_same_domain "$concurrent_home"

# The DNS root is already a fully qualified name.  Its TXT owner must render
# as a single dot, not as two dots, when the second query triggers the marker.
root_home=$(new_home root-domain)
set +e
HOME="$root_home" "$WRAPPER" @127.0.0.1 -p 9 . A +time=1 +tries=1 > "$TEST_ROOT/root-1.out" 2> "$TEST_ROOT/root-1.err"
root_rc1=$?
HOME="$root_home" "$WRAPPER" @127.0.0.1 -p 9 . A +time=1 +tries=1 > "$TEST_ROOT/root-2.out" 2> "$TEST_ROOT/root-2.err"
root_rc2=$?
set -e
if [ "$root_rc1" -ne 9 ] || [ "$root_rc2" -ne 9 ]; then
    fail "root-domain test did not preserve expected local connection-failure status (got $root_rc1/$root_rc2)"
fi
assert_marker_count "$TEST_ROOT/root-1.out" 0 'first root-domain lookup added marker'
assert_marker_count "$TEST_ROOT/root-2.out" 0 'second root-domain lookup added marker'
assert_state_counts "$root_home" '{".": 2}' 'root-domain counter is wrong'

# NONE and RESERVED0 are DNS classes, not extra host names.  The same two
# domains cross the second-query threshold together, then remain quiet on 3.
class_home=$(new_home class-special)
set +e
HOME="$class_home" "$WRAPPER" @127.0.0.1 -p 9 none-class-wrapper.example NONE A reserved0-class-wrapper.example RESERVED0 A +short +time=1 +tries=1 > "$TEST_ROOT/class-special-1.out" 2> "$TEST_ROOT/class-special-1.err"
class_special_rc1=$?
HOME="$class_home" "$WRAPPER" @127.0.0.1 -p 9 none-class-wrapper.example NONE A reserved0-class-wrapper.example RESERVED0 A +short +time=1 +tries=1 > "$TEST_ROOT/class-special-2.out" 2> "$TEST_ROOT/class-special-2.err"
class_special_rc2=$?
HOME="$class_home" "$WRAPPER" @127.0.0.1 -p 9 none-class-wrapper.example NONE A reserved0-class-wrapper.example RESERVED0 A +short +time=1 +tries=1 > "$TEST_ROOT/class-special-3.out" 2> "$TEST_ROOT/class-special-3.err"
class_special_rc3=$?
set -e
if [ "$class_special_rc1" -ne 9 ] || [ "$class_special_rc2" -ne 9 ] || [ "$class_special_rc3" -ne 9 ]; then
    fail "NONE/RESERVED0 test did not preserve expected local failure status"
fi
assert_marker_count "$TEST_ROOT/class-special-1.out" 0 'first NONE/RESERVED0 query added marker'
assert_marker_count "$TEST_ROOT/class-special-2.out" 2 'second NONE/RESERVED0 query did not trigger exactly once per real domain'
assert_marker_count "$TEST_ROOT/class-special-3.out" 0 'third NONE/RESERVED0 query added marker'
assert_state_counts "$class_home" '{"none-class-wrapper.example": 3, "reserved0-class-wrapper.example": 3}' 'NONE or RESERVED0 became a phantom domain'

# Numeric type/class tokens are only valid through the unsigned 16-bit limit.
valid_u16_home=$(new_home valid-u16)
set +e
HOME="$valid_u16_home" "$WRAPPER" @127.0.0.1 -p 9 valid-type-wrapper.example TYPE65535 valid-class-wrapper.example CLASS65535 A +short +time=1 +tries=1 > "$TEST_ROOT/valid-u16-1.out" 2> "$TEST_ROOT/valid-u16-1.err"
valid_u16_rc1=$?
HOME="$valid_u16_home" "$WRAPPER" @127.0.0.1 -p 9 valid-type-wrapper.example TYPE65535 valid-class-wrapper.example CLASS65535 A +short +time=1 +tries=1 > "$TEST_ROOT/valid-u16-2.out" 2> "$TEST_ROOT/valid-u16-2.err"
valid_u16_rc2=$?
set -e
if [ "$valid_u16_rc1" -ne 9 ] || [ "$valid_u16_rc2" -ne 9 ]; then
    fail "TYPE65535/CLASS65535 test did not preserve expected local failure status"
fi
assert_marker_count "$TEST_ROOT/valid-u16-1.out" 0 'first TYPE65535/CLASS65535 query added marker'
assert_marker_count "$TEST_ROOT/valid-u16-2.out" 2 'valid TYPE65535/CLASS65535 were parsed as domains'
assert_state_counts "$valid_u16_home" '{"valid-type-wrapper.example": 2, "valid-class-wrapper.example": 2}' 'valid numeric type/class created a phantom domain'

# Out-of-range TYPE/CLASS tokens are ordinary second query names, just as dig
# interprets them; each invocation therefore contains two domain occurrences.
type_overflow_home=$(new_home type-overflow)
set +e
HOME="$type_overflow_home" "$WRAPPER" @127.0.0.1 -p 9 type-overflow-primary.example TYPE65536 A +short +time=1 +tries=1 > "$TEST_ROOT/type-overflow-1.out" 2> "$TEST_ROOT/type-overflow-1.err"
type_overflow_rc1=$?
HOME="$type_overflow_home" "$WRAPPER" @127.0.0.1 -p 9 type-overflow-primary.example TYPE65536 A +short +time=1 +tries=1 > "$TEST_ROOT/type-overflow-2.out" 2> "$TEST_ROOT/type-overflow-2.err"
type_overflow_rc2=$?
set -e
if [ "$type_overflow_rc1" -ne 9 ] || [ "$type_overflow_rc2" -ne 9 ]; then
    fail "TYPE65536 overflow test did not preserve expected local failure status"
fi
assert_marker_count "$TEST_ROOT/type-overflow-1.out" 0 'first TYPE65536 invocation added marker'
assert_marker_count "$TEST_ROOT/type-overflow-2.out" 2 'TYPE65536 was not counted as a second domain'
assert_state_counts "$type_overflow_home" '{"type-overflow-primary.example": 2, "type65536": 2}' 'TYPE65536 state did not include two normalized domains'

class_overflow_home=$(new_home class-overflow)
set +e
HOME="$class_overflow_home" "$WRAPPER" @127.0.0.1 -p 9 class-overflow-primary.example CLASS65536 A +short +time=1 +tries=1 > "$TEST_ROOT/class-overflow-1.out" 2> "$TEST_ROOT/class-overflow-1.err"
class_overflow_rc1=$?
HOME="$class_overflow_home" "$WRAPPER" @127.0.0.1 -p 9 class-overflow-primary.example CLASS65536 A +short +time=1 +tries=1 > "$TEST_ROOT/class-overflow-2.out" 2> "$TEST_ROOT/class-overflow-2.err"
class_overflow_rc2=$?
set -e
if [ "$class_overflow_rc1" -ne 9 ] || [ "$class_overflow_rc2" -ne 9 ]; then
    fail "CLASS65536 overflow test did not preserve expected local failure status"
fi
assert_marker_count "$TEST_ROOT/class-overflow-1.out" 0 'first CLASS65536 invocation added marker'
assert_marker_count "$TEST_ROOT/class-overflow-2.out" 2 'CLASS65536 was not counted as a second domain'
assert_state_counts "$class_overflow_home" '{"class-overflow-primary.example": 2, "class65536": 2}' 'CLASS65536 state did not include two normalized domains'

# Escaped DNS whitespace shares one canonical key across direct argv, a file
# batch, and an escaped stdin batch: calls 1/2/3 yield marker counts 0/1/0.
escape_home=$(new_home escaped-cross-interface)
escaped_name='escaped\032name.example'
printf '%s\n' '@127.0.0.1 -p 9 escaped\032name.example A +short +time=1 +tries=1' > "$TEST_ROOT/escaped-name.batch"
set +e
HOME="$escape_home" "$WRAPPER" @127.0.0.1 -p 9 "$escaped_name" A +short +time=1 +tries=1 > "$TEST_ROOT/escaped-direct.out" 2> "$TEST_ROOT/escaped-direct.err"
escaped_direct_rc=$?
HOME="$escape_home" "$WRAPPER" -f "$TEST_ROOT/escaped-name.batch" > "$TEST_ROOT/escaped-file.out" 2> "$TEST_ROOT/escaped-file.err"
escaped_file_rc=$?
printf '%s\n' '@127.0.0.1 -p 9 escaped\032name.example MX +short +time=1 +tries=1' | HOME="$escape_home" "$WRAPPER" -f - > "$TEST_ROOT/escaped-stdin.out" 2> "$TEST_ROOT/escaped-stdin.err"
escaped_stdin_rc=$?
set -e
if [ "$escaped_direct_rc" -ne 9 ] || [ "$escaped_file_rc" -ne 9 ] || [ "$escaped_stdin_rc" -ne 9 ]; then
    fail "escaped direct/file/stdin test did not preserve expected local failure status"
fi
assert_marker_count "$TEST_ROOT/escaped-direct.out" 0 'direct escaped DNS name added marker'
assert_marker_count "$TEST_ROOT/escaped-file.out" 1 'file batch did not share escaped DNS key with direct argv'
assert_marker_count "$TEST_ROOT/escaped-stdin.out" 0 'stdin batch retriggered escaped DNS key'
assert_state_counts "$escape_home" '{"escaped\\032name.example": 3}' 'escaped DNS name did not retain one safe state key across interfaces'

# -x must key and render the reverse pointer, not the literal IPv4/IPv6 input.
assert_reverse_pointer_sequence() {
    label=$1
    address=$2
    pointer=$3
    home=$(new_home "reverse-$label")
    set +e
    HOME="$home" "$WRAPPER" @127.0.0.1 -p 9 -x "$address" +time=1 +tries=1 > "$TEST_ROOT/reverse-$label-1.out" 2> "$TEST_ROOT/reverse-$label-1.err"
    reverse_rc1=$?
    HOME="$home" "$WRAPPER" @127.0.0.1 -p 9 -x "$address" +time=1 +tries=1 > "$TEST_ROOT/reverse-$label-2.out" 2> "$TEST_ROOT/reverse-$label-2.err"
    reverse_rc2=$?
    HOME="$home" "$WRAPPER" @127.0.0.1 -p 9 -x "$address" +time=1 +tries=1 > "$TEST_ROOT/reverse-$label-3.out" 2> "$TEST_ROOT/reverse-$label-3.err"
    reverse_rc3=$?
    set -e
    if [ "$reverse_rc1" -ne 9 ] || [ "$reverse_rc2" -ne 9 ] || [ "$reverse_rc3" -ne 9 ]; then
        fail "$label reverse lookup did not preserve expected local failure status"
    fi
    assert_marker_count "$TEST_ROOT/reverse-$label-1.out" 0 "first $label reverse lookup added marker"
    assert_marker_count "$TEST_ROOT/reverse-$label-2.out" 0 "second $label reverse lookup added marker"
    assert_marker_count "$TEST_ROOT/reverse-$label-3.out" 0 "third $label reverse lookup added marker"
    expected_counts=$(printf '{"%s": 3}' "$pointer")
    assert_state_counts "$home" "$expected_counts" "$label reverse pointer state is wrong"
}

assert_reverse_pointer_sequence ipv4 192.0.2.1 1.2.0.192.in-addr.arpa
assert_reverse_pointer_sequence ipv6 2001:db8::1 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa

# Only the final top-level -f is active.  An earlier stdin batch and an earlier
# file batch must not be consumed, queried, or added to wrapper state.
last_batch_home=$(new_home last-top-level-batch)
printf '%s\n' '@127.0.0.1 -p 9 first-top-level-wrapper.example A +short +time=1 +tries=1' > "$TEST_ROOT/first-top-level.batch"
printf '%s\n' '@127.0.0.1 -p 9 last-top-level-wrapper.example A +short +time=1 +tries=1' > "$TEST_ROOT/last-top-level.batch"
set +e
printf '%s\n' '@127.0.0.1 -p 9 stdin-overridden-wrapper.example A +short +time=1 +tries=1' | HOME="$last_batch_home" "$WRAPPER" -f - -f "$TEST_ROOT/last-top-level.batch" > "$TEST_ROOT/last-top-level-1.out" 2> "$TEST_ROOT/last-top-level-1.err"
last_batch_rc1=$?
HOME="$last_batch_home" "$WRAPPER" -f "$TEST_ROOT/first-top-level.batch" -f "$TEST_ROOT/last-top-level.batch" > "$TEST_ROOT/last-top-level-2.out" 2> "$TEST_ROOT/last-top-level-2.err"
last_batch_rc2=$?
set -e
if [ "$last_batch_rc1" -ne 9 ] || [ "$last_batch_rc2" -ne 9 ]; then
    fail "multiple top-level -f test did not preserve expected local failure status"
fi
assert_marker_count "$TEST_ROOT/last-top-level-1.out" 0 'first active final batch added marker'
assert_marker_count "$TEST_ROOT/last-top-level-2.out" 1 'second active final batch did not add marker'
assert_state_counts "$last_batch_home" '{"last-top-level-wrapper.example": 2}' 'an overridden top-level -f batch polluted state'


# Stdin batches preserve state across invocations and query types.
stdin_home=$(new_home stdin)
printf '%s\n' 'stdin-wrapper.example A +short' | HOME="$stdin_home" "$WRAPPER" -f - > "$TEST_ROOT/stdin-1.out"
printf '%s\n' 'stdin-wrapper.example MX +short' | HOME="$stdin_home" "$WRAPPER" -f - > "$TEST_ROOT/stdin-2.out"
assert_marker_count "$TEST_ROOT/stdin-1.out" 0 'first stdin batch added marker'
assert_marker_count "$TEST_ROOT/stdin-2.out" 1 'stdin batch did not share the per-domain counter across types'
assert_state_counts "$stdin_home" '{"stdin-wrapper.example": 2}' 'stdin-batch counter is wrong'

# IXFR=<serial> is a query type, not an extra domain token.  A closed local UDP
# port makes this deterministic while preserving dig's documented exit status.
ixfr_home=$(new_home ixfr)
set +e
HOME="$ixfr_home" "$WRAPPER" @127.0.0.1 -p 9 ixfr-wrapper.example ixfr=1 +short +time=1 +tries=1 > "$TEST_ROOT/ixfr-1.out" 2> "$TEST_ROOT/ixfr-1.err"
ixfr_rc1=$?
HOME="$ixfr_home" "$WRAPPER" @127.0.0.1 -p 9 ixfr-wrapper.example IXFR=1 +short +time=1 +tries=1 > "$TEST_ROOT/ixfr-2.out" 2> "$TEST_ROOT/ixfr-2.err"
ixfr_rc2=$?
set -e
if [ "$ixfr_rc1" -ne 9 ] || [ "$ixfr_rc2" -ne 9 ]; then
    fail "IXFR test did not preserve dig's expected connection-failure status (got $ixfr_rc1/$ixfr_rc2)"
fi
assert_marker_count "$TEST_ROOT/ixfr-1.out" 0 'first IXFR serial query added marker'
assert_marker_count "$TEST_ROOT/ixfr-2.out" 1 'IXFR serial syntax was not parsed as one query'
assert_state_counts "$ixfr_home" '{"ixfr-wrapper.example": 2}' 'IXFR serial token was counted as a domain'

# Generic CLASS<number> tokens are DNS classes, not domain names.
class_home=$(new_home class)
HOME="$class_home" "$WRAPPER" class-wrapper.example CLASS3 A +short > "$TEST_ROOT/class-1.out"
HOME="$class_home" "$WRAPPER" class-wrapper.example class255 MX +short > "$TEST_ROOT/class-2.out"
assert_marker_count "$TEST_ROOT/class-1.out" 0 'first generic CLASS lookup added marker'
assert_marker_count "$TEST_ROOT/class-2.out" 1 'CLASS<number> syntax was parsed as a domain'
assert_state_counts "$class_home" '{"class-wrapper.example": 2}' 'CLASS<number> token changed state accounting'

# Help and version pass through without creating or advancing a counter.
meta_home=$(new_home help-version)
meta_name=help-version-wrapper.example
HOME="$meta_home" "$WRAPPER" "$meta_name" -h > "$TEST_ROOT/help.out"
HOME="$meta_home" "$WRAPPER" "$meta_name" -v > "$TEST_ROOT/version.out"
assert_marker_count "$TEST_ROOT/help.out" 0 'help output contained marker'
assert_marker_count "$TEST_ROOT/version.out" 0 'version output contained marker'
[ ! -e "$meta_home/.cache/dig-zcode-wrapper/state.json" ] || fail 'help or version created state'
HOME="$meta_home" "$WRAPPER" "$meta_name" A +short > "$TEST_ROOT/meta-1.out"
HOME="$meta_home" "$WRAPPER" "$meta_name" AAAA +short > "$TEST_ROOT/meta-2.out"
assert_marker_count "$TEST_ROOT/meta-1.out" 0 'help or version advanced the counter'
assert_marker_count "$TEST_ROOT/meta-2.out" 1 'normal lookup after help/version did not reach second call'
assert_state_counts "$meta_home" '{"help-version-wrapper.example": 2}' 'help/version affected normal state accounting'

# Invalid command lines must be byte-for-byte transparent and must not count.
invalid_home=$(new_home invalid)
set +e
HOME="$invalid_home" "$WRAPPER" --definitely-not-a-dig-option invalid-wrapper.example TXT +short > "$TEST_ROOT/invalid-wrapper-1.out" 2> "$TEST_ROOT/invalid-wrapper-1.err"
invalid_rc1=$?
HOME="$invalid_home" "$WRAPPER" --definitely-not-a-dig-option invalid-wrapper.example TXT +short > "$TEST_ROOT/invalid-wrapper-2.out" 2> "$TEST_ROOT/invalid-wrapper-2.err"
invalid_rc2=$?
HOME="$invalid_home" "$REAL_DIG" --definitely-not-a-dig-option invalid-wrapper.example TXT +short > "$TEST_ROOT/invalid-real.out" 2> "$TEST_ROOT/invalid-real.err"
invalid_real_rc=$?
set -e
if [ "$invalid_rc1" -ne "$invalid_real_rc" ] || [ "$invalid_rc2" -ne "$invalid_real_rc" ] || \
   ! cmp -s "$TEST_ROOT/invalid-wrapper-1.out" "$TEST_ROOT/invalid-real.out" || \
   ! cmp -s "$TEST_ROOT/invalid-wrapper-2.out" "$TEST_ROOT/invalid-real.out" || \
   ! cmp -s "$TEST_ROOT/invalid-wrapper-1.err" "$TEST_ROOT/invalid-real.err" || \
   ! cmp -s "$TEST_ROOT/invalid-wrapper-2.err" "$TEST_ROOT/invalid-real.err"; then
    fail 'invalid option behavior differs from real dig'
fi
[ ! -e "$invalid_home/.cache/dig-zcode-wrapper/state.json" ] || fail 'invalid option created state'
HOME="$invalid_home" "$WRAPPER" invalid-wrapper.example A +short > "$TEST_ROOT/invalid-after-1.out"
HOME="$invalid_home" "$WRAPPER" invalid-wrapper.example MX +short > "$TEST_ROOT/invalid-after-2.out"
assert_marker_count "$TEST_ROOT/invalid-after-1.out" 0 'invalid option advanced the counter'
assert_marker_count "$TEST_ROOT/invalid-after-2.out" 1 'valid second query after invalid option did not trigger'
assert_state_counts "$invalid_home" '{"invalid-wrapper.example": 2}' 'invalid option polluted state'

# If state setup fails, stdout, stderr, and exit status remain identical to dig.
bad_home="$TEST_ROOT/home-without-cache"
mkdir -m 700 "$bad_home"
set +e
HOME="$bad_home" "$WRAPPER" @127.0.0.1 -p 9 state-failure-wrapper.example A +short +time=1 +tries=1 > "$TEST_ROOT/state-wrapper.out" 2> "$TEST_ROOT/state-wrapper.err"
state_wrapper_rc=$?
HOME="$bad_home" "$REAL_DIG" @127.0.0.1 -p 9 state-failure-wrapper.example A +short +time=1 +tries=1 > "$TEST_ROOT/state-real.out" 2> "$TEST_ROOT/state-real.err"
state_real_rc=$?
set -e
if [ "$state_wrapper_rc" -ne "$state_real_rc" ] || \
   ! cmp -s "$TEST_ROOT/state-wrapper.out" "$TEST_ROOT/state-real.out" || \
   ! cmp -s "$TEST_ROOT/state-wrapper.err" "$TEST_ROOT/state-real.err"; then
    fail 'state failure was not transparent to the real dig command'
fi
[ ! -e "$bad_home/.cache" ] || fail 'state failure created a cache directory'

# Once -t/-c has explicitly consumed a type/class, a following bare TYPE
# token is a hostname.  Cover both separate and attached spellings.
explicit_option_home=$(new_home explicit-type-class-options)
set +e
HOME="$explicit_option_home" "$WRAPPER" @127.0.0.1 -p 9 -t A TYPE65535 +short +time=1 +tries=1 > "$TEST_ROOT/explicit-t-separate.out" 2> "$TEST_ROOT/explicit-t-separate.err"
explicit_t_separate_rc=$?
HOME="$explicit_option_home" "$WRAPPER" @127.0.0.1 -p 9 -tA TYPE65535 +short +time=1 +tries=1 > "$TEST_ROOT/explicit-t-attached.out" 2> "$TEST_ROOT/explicit-t-attached.err"
explicit_t_attached_rc=$?
HOME="$explicit_option_home" "$WRAPPER" @127.0.0.1 -p 9 -c IN TYPE65535 +short +time=1 +tries=1 > "$TEST_ROOT/explicit-c-separate.out" 2> "$TEST_ROOT/explicit-c-separate.err"
explicit_c_separate_rc=$?
HOME="$explicit_option_home" "$WRAPPER" @127.0.0.1 -p 9 -cIN TYPE65535 +short +time=1 +tries=1 > "$TEST_ROOT/explicit-c-attached.out" 2> "$TEST_ROOT/explicit-c-attached.err"
explicit_c_attached_rc=$?
set -e
if [ "$explicit_t_separate_rc" -ne 9 ] || [ "$explicit_t_attached_rc" -ne 9 ] || [ "$explicit_c_separate_rc" -ne 9 ] || [ "$explicit_c_attached_rc" -ne 9 ]; then
    fail 'explicit -t/-c bare-type host test did not preserve expected local failure status'
fi
assert_marker_count "$TEST_ROOT/explicit-t-separate.out" 0 'first explicit -t bare TYPE host added marker'
assert_marker_count "$TEST_ROOT/explicit-t-attached.out" 1 'attached -t did not treat bare TYPE as the same host'
assert_marker_count "$TEST_ROOT/explicit-c-separate.out" 0 'separate -c retriggered bare TYPE host'
assert_marker_count "$TEST_ROOT/explicit-c-attached.out" 0 'attached -c retriggered bare TYPE host'
assert_state_counts "$explicit_option_home" '{"type65535": 4}' 'explicit -t/-c did not track bare TYPE65535 as one host'

# Exact -h/-v lines inside file and stdin batches must be passed through like
# real dig and must not create state.  They are not top-level help/version args.
meta_batch_home=$(new_home batch-help-version)
printf '%s\n' '-h' > "$TEST_ROOT/batch-help.batch"
printf '%s\n' '-v' > "$TEST_ROOT/batch-version.batch"
"$PYTHON" - "$WRAPPER" "$REAL_DIG" "$meta_batch_home" "$TEST_ROOT/batch-help.batch" "$TEST_ROOT/batch-version.batch" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

wrapper, real_dig, home, help_file, version_file = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home
cases = (
    ("file batch -h", ["-f", help_file], None),
    ("file batch -v", ["-f", version_file], None),
    ("stdin batch -h", ["-f", "-"], b"-h\n"),
    ("stdin batch -v", ["-f", "-"], b"-v\n"),
)
for label, arguments, payload in cases:
    try:
        wrapped = subprocess.run(
            [wrapper] + arguments,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
        real = subprocess.run(
            [real_dig] + arguments,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL: {} timed out after 5 seconds".format(label))
    if (
        wrapped.returncode != real.returncode
        or wrapped.stdout != real.stdout
        or wrapped.stderr != real.stderr
    ):
        raise SystemExit("FAIL: {} differs from real dig".format(label))
    if b"traceback" in (wrapped.stdout + wrapped.stderr).lower():
        raise SystemExit("FAIL: {} emitted a traceback".format(label))
state_directory = Path(home) / ".cache" / "dig-zcode-wrapper"
if state_directory.exists() or state_directory.is_symlink():
    raise SystemExit("FAIL: batch -h/-v created wrapper state")
PY

# Inline #, ;, and quote are DNS-name bytes; only an entire trimmed batch line
# starting with # or ; is a comment. DNS whitespace is covered above through
# its portable \032 presentation instead of shell-style backslash grouping.
inline_home=$(new_home inline-batch-syntax)
printf '%s\n' \
    '# whole-line comment' \
    '; whole-line comment' \
    '@127.0.0.1 -p 9 inline#hash-wrapper.example A +short +time=1 +tries=1' \
    '@127.0.0.1 -p 9 inline;semi-wrapper.example A +short +time=1 +tries=1' \
    '@127.0.0.1 -p 9 quote"name-wrapper.example A +short +time=1 +tries=1' > "$TEST_ROOT/inline-syntax.batch"
set +e
HOME="$inline_home" "$WRAPPER" @127.0.0.1 -p 9 inline#hash-wrapper.example A 'inline;semi-wrapper.example' A 'quote"name-wrapper.example' A +short +time=1 +tries=1 > "$TEST_ROOT/inline-direct.out" 2> "$TEST_ROOT/inline-direct.err"
inline_direct_rc=$?
HOME="$inline_home" "$WRAPPER" -f "$TEST_ROOT/inline-syntax.batch" > "$TEST_ROOT/inline-file.out" 2> "$TEST_ROOT/inline-file.err"
inline_file_rc=$?
printf '%s\n' \
    '# whole-line comment' \
    '; whole-line comment' \
    '@127.0.0.1 -p 9 inline#hash-wrapper.example A +short +time=1 +tries=1' \
    '@127.0.0.1 -p 9 inline;semi-wrapper.example A +short +time=1 +tries=1' \
    '@127.0.0.1 -p 9 quote"name-wrapper.example A +short +time=1 +tries=1' | HOME="$inline_home" "$WRAPPER" -f - > "$TEST_ROOT/inline-stdin.out" 2> "$TEST_ROOT/inline-stdin.err"
inline_stdin_rc=$?
set -e
if [ "$inline_direct_rc" -ne 9 ] || [ "$inline_file_rc" -ne 9 ] || [ "$inline_stdin_rc" -ne 9 ]; then
    fail 'inline batch syntax test did not preserve expected local failure status'
fi
assert_marker_count "$TEST_ROOT/inline-direct.out" 0 'direct inline-name queries added marker'
assert_marker_count "$TEST_ROOT/inline-file.out" 3 'file batch did not share all inline name bytes with direct argv'
assert_marker_count "$TEST_ROOT/inline-stdin.out" 0 'stdin batch retriggered an inline-name key'
assert_state_counts "$inline_home" '{"inline\\035hash-wrapper.example": 3, "inline\\059semi-wrapper.example": 3, "quote\\034name-wrapper.example": 3}' 'inline quote/#/; batch names did not preserve canonical keys'

# A top-level -t/-c is left-to-right and scoped to that command: a bare A
# before it remains a type, never a phantom hostname.  Batch lines begin with
# fresh positional semantics even if the top-level command carries -t.
order_home=$(new_home explicit-order)
order_batch="$TEST_ROOT/explicit-order.batch"
printf '%s\n' \
    '@127.0.0.1 -p 9 order-batch-t-separate.example A -t MX +short +time=1 +tries=1' \
    '@127.0.0.1 -p 9 order-batch-t-attached.example A -tMX +short +time=1 +tries=1' > "$order_batch"
"$PYTHON" - "$WRAPPER" "$MARKER" "$order_home" "$order_batch" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

wrapper, marker, home, batch = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home
marker_bytes = marker.encode("utf-8")
base = ["@127.0.0.1", "-p", "9"]
tail = ["+short", "+time=1", "+tries=1"]
cases = (
    ("direct -t separate", base + ["order-t-separate.example", "A", "-t", "MX"] + tail, "order-t-separate.example"),
    ("direct -t attached", base + ["order-t-attached.example", "A", "-tMX"] + tail, "order-t-attached.example"),
    ("direct -c separate", base + ["order-c-separate.example", "A", "-c", "IN"] + tail, "order-c-separate.example"),
    ("direct -c attached", base + ["order-c-attached.example", "A", "-cIN"] + tail, "order-c-attached.example"),
)
expected = {}
for label, arguments, key in cases:
    for attempt, expected_markers in ((1, 0), (2, 0)):
        try:
            result = subprocess.run(
                [wrapper] + arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("FAIL: {} attempt {} timed out".format(label, attempt))
        if result.returncode != 9:
            raise SystemExit("FAIL: {} attempt {} rc {} != 9".format(label, attempt, result.returncode))
        if result.stdout.count(marker_bytes) != expected_markers:
            raise SystemExit("FAIL: {} attempt {} marker count is wrong".format(label, attempt))
    expected[key] = 2
batch_args = ["-t", "MX", "-f", batch]
for attempt, expected_markers in ((1, 0), (2, 0)):
    try:
        result = subprocess.run(
            [wrapper] + batch_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL: top-level -t batch attempt {} timed out".format(attempt))
    if result.returncode != 9 or result.stdout.count(marker_bytes) != expected_markers:
        raise SystemExit("FAIL: top-level -t batch semantics are wrong on attempt {}".format(attempt))
expected.update({"order-batch-t-separate.example": 2, "order-batch-t-attached.example": 2})
state_path = Path(home) / ".cache" / "dig-zcode-wrapper" / "state.json"
with state_path.open(encoding="utf-8") as handle:
    state = json.load(handle)
if state.get("version") != 2 or state.get("counts") != expected:
    raise SystemExit("FAIL: -t/-c ordering created a phantom token or wrong state: {!r}".format(state))
PY

# A regular nested -f inside a batch is deliberately not modeled; it must fall
# through to the real binary byte-for-byte without creating wrapper state.
nested_regular_home=$(new_home nested-regular)
nested_regular_inner="$TEST_ROOT/nested-regular-inner.batch"
nested_regular_outer="$TEST_ROOT/nested-regular-outer.batch"
printf '%s\n' '@127.0.0.1 -p 9 nested-regular-inner.example A +short +time=1 +tries=1' > "$nested_regular_inner"
printf '%s\n' "-f $nested_regular_inner @127.0.0.1 -p 9 +short +time=1 +tries=1" > "$nested_regular_outer"
assert_nested_batch_transparent 'ordinary nested -f batch' "$nested_regular_home" "$nested_regular_outer"

# -x has Apple-compatible literal-dot fallback for non-IPv6 spellings; -i only
# affects a following IPv6 -x, including a top-level default for batch lines.
x_variants_home=$(new_home x-variants)
x_top_i_batch="$TEST_ROOT/x-top-i.batch"
x_scoped_batch="$TEST_ROOT/x-scoped.batch"
"$PYTHON" - "$WRAPPER" "$MARKER" "$x_variants_home" "$x_top_i_batch" "$x_scoped_batch" <<'PY'
import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

wrapper, marker, home, top_batch, scoped_batch = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home
marker_bytes = marker.encode("utf-8")


def reverse_literal(value):
    return ".".join(reversed(value.split("."))) + ".in-addr.arpa"


def ip6_pointer(value, use_int):
    pointer = ipaddress.ip_address(value).reverse_pointer
    return pointer[:-4] + "int" if use_int else pointer


def record(owner):
    return '{}.\t60\tIN\tTXT\t"{}"'.format(owner, marker).encode("ascii")


def run_twice(label, arguments, owner):
    for attempt, expected in ((1, []), (2, [])):
        try:
            result = subprocess.run(
                [wrapper] + arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("FAIL: {} attempt {} timed out".format(label, attempt))
        lines = [line for line in result.stdout.splitlines() if marker_bytes in line]
        if result.returncode != 9 or lines != expected:
            raise SystemExit("FAIL: {} attempt {} has wrong rc/marker owner".format(label, attempt))

base = ["@127.0.0.1", "-p", "9"]
tail = ["+time=1", "+tries=1"]
variants = (
    ("partial IPv4", "192.0.2", reverse_literal("192.0.2")),
    ("leading-zero IPv4", "192.000.002.001", reverse_literal("192.000.002.001")),
    ("non-IP dotted", "not.ip.name", reverse_literal("not.ip.name")),
    ("dot-reverse spelling", "1.2.3.4.in-addr.arpa", reverse_literal("1.2.3.4.in-addr.arpa")),
)
expected_counts = {}
for label, value, owner in variants:
    run_twice(label, base + ["-x", value] + tail, owner)
    expected_counts[owner] = 2
before_value = "2001:db8::2"
after_value = "2001:db8::3"
before_owner = ip6_pointer(before_value, True)
after_owner = ip6_pointer(after_value, False)
run_twice("-i before IPv6 -x", base + ["-i", "-x", before_value] + tail, before_owner)
run_twice("-i after IPv6 -x", base + ["-x", after_value, "-i"] + tail, after_owner)
expected_counts[before_owner] = 2
expected_counts[after_owner] = 2
Path(top_batch).write_text(
    "@127.0.0.1 -p 9 -x 2001:db8::4 +time=1 +tries=1\n",
    encoding="utf-8",
)
top_owner = ip6_pointer("2001:db8::4", True)
run_twice("top-level -i batch default", ["-i", "-f", top_batch], top_owner)
expected_counts[top_owner] = 2
Path(scoped_batch).write_text(
    "@127.0.0.1 -p 9 -x 2001:db8::5 -i +time=1 +tries=1\n"
    "@127.0.0.1 -p 9 -i -x 2001:db8::6 +time=1 +tries=1\n",
    encoding="utf-8",
)
scoped_arpa = ip6_pointer("2001:db8::5", False)
scoped_int = ip6_pointer("2001:db8::6", True)
for attempt, expected in ((1, []), (2, [])):
    try:
        result = subprocess.run(
            [wrapper, "-f", scoped_batch],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL: scoped IPv6 batch attempt {} timed out".format(attempt))
    lines = [line for line in result.stdout.splitlines() if marker_bytes in line]
    if result.returncode != 9 or lines != expected:
        raise SystemExit("FAIL: scoped IPv6 batch semantics are wrong on attempt {}".format(attempt))
expected_counts[scoped_arpa] = 2
expected_counts[scoped_int] = 2
state_path = Path(home) / ".cache" / "dig-zcode-wrapper" / "state.json"
with state_path.open(encoding="utf-8") as handle:
    state = json.load(handle)
if state.get("version") != 2 or state.get("counts") != expected_counts:
    raise SystemExit("FAIL: -x fallback/-i state is wrong: {!r}".format(state))
PY

# FIFO state.json must never block the wrapper, and bool is not a valid counter
# even though it is an int subclass.  Both corrupted states fail open within 3s.
assert_state_failure_transparent() {
    label=$1
    home=$2
    name=$3
    "$PYTHON" - "$WRAPPER" "$REAL_DIG" "$MARKER" "$home" "$name" "$label" <<'PY'
import os
import subprocess
import sys

wrapper, real_dig, marker, home, name, label = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home
arguments = ["@127.0.0.1", "-p", "9", name, "A", "+short", "+time=1", "+tries=1"]
try:
    wrapped = subprocess.run(
        [wrapper] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=3,
        check=False,
    )
    real = subprocess.run(
        [real_dig] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=3,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit("FAIL: {} did not remain transparent within 3 seconds".format(label))
if marker.encode("utf-8") in (wrapped.stdout + wrapped.stderr):
    raise SystemExit("FAIL: {} appended a marker despite invalid state".format(label))
if b"traceback" in (wrapped.stdout + wrapped.stderr).lower():
    raise SystemExit("FAIL: {} emitted a traceback".format(label))
if (
    wrapped.returncode != real.returncode
    or wrapped.stdout != real.stdout
    or wrapped.stderr != real.stderr
):
    raise SystemExit("FAIL: {} differs from real dig during state failure".format(label))
PY
}

fifo_home=$(new_home fifo-state)
fifo_state_directory="$fifo_home/.cache/dig-zcode-wrapper"
mkdir -m 700 "$fifo_state_directory"
printf '%s\n' 'stateful-dig-wrapper:any-query:v2' > "$fifo_state_directory/.owner"
chmod 600 "$fifo_state_directory/.owner"
mkfifo "$fifo_state_directory/state.json"
assert_state_failure_transparent 'FIFO state.json' "$fifo_home" fifo-state-wrapper.example
[ -p "$fifo_state_directory/state.json" ] || fail 'FIFO state.json was unexpectedly replaced'

bool_home=$(new_home bool-state)
bool_state_directory="$bool_home/.cache/dig-zcode-wrapper"
mkdir -m 700 "$bool_state_directory"
printf '%s\n' 'stateful-dig-wrapper:any-query:v2' > "$bool_state_directory/.owner"
chmod 600 "$bool_state_directory/.owner"
printf '%s\n' '{"version": 2, "counts": {"bool-state-wrapper.example": true}}' > "$bool_state_directory/state.json"
cp "$bool_state_directory/state.json" "$TEST_ROOT/bool-state-original.json"
assert_state_failure_transparent 'bool counter state.json' "$bool_home" bool-state-wrapper.example
cmp -s "$bool_state_directory/state.json" "$TEST_ROOT/bool-state-original.json" || fail 'bool counter state was overwritten instead of fail-open'

# A loopback answer makes real dig silent under +short.  Closing the stdout
# reader on call two therefore exercises only the wrapper marker write.
broken_pipe_home=$(new_home broken-pipe)
"$PYTHON" - "$WRAPPER" "$REAL_DIG" "$MARKER" "$broken_pipe_home" <<'PY'
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

wrapper, real_dig, marker, home = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(0.1)
port = sock.getsockname()[1]
stop = threading.Event()


def serve():
    while not stop.is_set():
        try:
            packet, address = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            index = 12
            while packet[index]:
                index += packet[index] + 1
            index += 1
            question = packet[12:index + 4]
        except IndexError:
            continue
        response = packet[:2] + b"\x81\x80" + packet[4:6] + b"\x00" * 6 + question
        try:
            sock.sendto(response, address)
        except OSError:
            return


def closed_stdout(command, label, arguments):
    process = subprocess.Popen(
        [command] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdout.close()
    try:
        return_code = process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise SystemExit("FAIL: {} timed out with closed stdout".format(label))
    return return_code, process.stderr.read()


thread = threading.Thread(target=serve, daemon=True)
thread.start()
arguments = ["@127.0.0.1", "-p", str(port), "broken-pipe-wrapper.example", "A", "+short", "+time=1", "+tries=1"]
try:
    first = subprocess.run(
        [wrapper] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=3,
        check=False,
    )
    if first.returncode != 0 or marker.encode("utf-8") in first.stdout:
        raise SystemExit("FAIL: broken-pipe setup did not establish first count")
    wrapper_rc, wrapper_stderr = closed_stdout(wrapper, "wrapper", arguments)
    real_rc, real_stderr = closed_stdout(real_dig, "real dig", arguments)
    if wrapper_rc != real_rc:
        raise SystemExit("FAIL: broken-pipe wrapper rc differs from real dig")
    if wrapper_stderr != real_stderr or b"traceback" in wrapper_stderr.lower():
        raise SystemExit("FAIL: broken-pipe marker write leaked stderr/traceback")
    state_path = Path(home) / ".cache" / "dig-zcode-wrapper" / "state.json"
    with state_path.open(encoding="utf-8") as handle:
        state = json.load(handle)
    if state.get("counts") != {"broken-pipe-wrapper.example": 2}:
        raise SystemExit("FAIL: broken-pipe second query did not persist count 2")
finally:
    stop.set()
    sock.close()
    thread.join(timeout=1)
PY

# SIGKILL is not signal()-able on macOS.  The helper must still terminate the
# subprocess by signal with no Python traceback or other output.
"$PYTHON" - "$WRAPPER" <<'PY'
import subprocess
import sys

wrapper = sys.argv[1]
code = "\n".join(
    (
        "import importlib.util",
        "import sys",
        "spec = importlib.util.spec_from_file_location('dig_wrapper_signal_test', sys.argv[1])",
        "module = importlib.util.module_from_spec(spec)",
        "spec.loader.exec_module(module)",
        "module.return_like_child(-9)",
    )
)
try:
    result = subprocess.run(
        [sys.executable, "-c", code, wrapper],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit("FAIL: return_like_child(-9) timed out")
if result.returncode != -9:
    raise SystemExit("FAIL: return_like_child(-9) rc {} != -9".format(result.returncode))
if result.stdout or result.stderr:
    raise SystemExit("FAIL: return_like_child(-9) emitted output")
PY

# Batch syntax is byte-oriented: only byte zero #/; starts a comment.  NBSP,
# VT, and an embedded CR stay inside an LF-delimited logical line.  The latter
# must preserve preceding -t/-i state instead of resetting it as a new command.
boundary_home=$(new_home batch-byte-boundaries)
boundary_batch="$TEST_ROOT/batch-byte-boundaries.batch"
"$PYTHON" - "$WRAPPER" "$MARKER" "$boundary_home" "$boundary_batch" <<'PY'
import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

wrapper, marker, home, batch = sys.argv[1:]
environment = os.environ.copy()
environment["HOME"] = home
marker_bytes = marker.encode("utf-8")
nbsp_name = "nbsp" + chr(0xA0) + "-wrapper.example"
vt_name = "vt" + chr(0x0B) + "-wrapper.example"
ip6_int_name = ipaddress.ip_address("2001:db8::7").reverse_pointer[:-4] + "int"
payload = "".join(
    (
        "# physical comment is ignored\n",
        "; physical comment is ignored\n",
        " # @127.0.0.1 -p 9 comment +short +time=1 +tries=1\n",
        " ; @127.0.0.1 -p 9 comment +short +time=1 +tries=1\n",
        "@127.0.0.1 -p 9 {} A +short +time=1 +tries=1\n".format(nbsp_name),
        "@127.0.0.1 -p 9 {} A +short +time=1 +tries=1\n".format(vt_name),
        "@127.0.0.1 -p 9 cr-order-wrapper.example A -t MX\rA +short +time=1 +tries=1\n",
        "@127.0.0.1 -p 9 -i\r-x 2001:db8::7 +short +time=1 +tries=1\n",
    )
)
Path(batch).write_bytes(payload.encode("utf-8"))


def run(label, arguments, input_data=None):
    try:
        result = subprocess.run(
            [wrapper] + arguments,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL: {} timed out".format(label))
    if result.returncode != 9:
        raise SystemExit("FAIL: {} rc {} != 9".format(label, result.returncode))
    if b"traceback" in (result.stdout + result.stderr).lower():
        raise SystemExit("FAIL: {} emitted a traceback".format(label))
    return result


# Direct argv establishes first counts.  File and stdin must then share those
# NBSP/VT keys.  stdin must use split("\n"), not splitlines(), and file input
# likewise must regard only LF as a physical line boundary.
direct = run(
    "direct NBSP/VT",
    [
        "@127.0.0.1", "-p", "9", nbsp_name, "A", vt_name, "A",
        "+short", "+time=1", "+tries=1",
    ],
)
from_file = run("file boundary batch", ["-f", batch])
from_stdin = run("stdin boundary batch", ["-f", "-"], payload.encode("utf-8"))
if direct.stdout.count(marker_bytes) != 0:
    raise SystemExit("FAIL: direct NBSP/VT first calls added a marker")
if from_file.stdout.count(marker_bytes) != 0:
    raise SystemExit("FAIL: file batch boundary semantics produced wrong markers")
if from_stdin.stdout.count(marker_bytes) != 0:
    raise SystemExit("FAIL: stdin batch boundary semantics produced wrong markers")

state_path = Path(home) / ".cache" / "dig-zcode-wrapper" / "state.json"
with state_path.open(encoding="utf-8") as handle:
    state = json.load(handle)
expected = {
    "\\035": 2,
    "\\059": 2,
    "comment": 4,
    "nbsp\\194\\160-wrapper.example": 3,
    "vt\\011-wrapper.example": 3,
    "cr-order-wrapper.example": 2,
    "a": 2,
    ip6_int_name: 2,
}
if state.get("version") != 2 or state.get("counts") != expected:
    raise SystemExit(
        "FAIL: comment/NBSP/VT/CR batch state is wrong: {!r}".format(state)
    )
PY

# Network metadata preservation and provenance are exercised separately in
# tests/test_overlay_evidence.py; local records are never network ANSWERs.

# Persistent local TXT overlay: +txt= (and non-hex +cookie=) register a value
# that is appended on every later TXT/ANY lookup.  Tokens are stripped before
# /usr/bin/dig sees them, so dig -h remains unchanged.
txt_home=$(new_home txt-overlay)
"$PYTHON" - "$WRAPPER" "$MARKER" "$txt_home" <<'TXTTEST'
import json
import os
import subprocess
import sys
from pathlib import Path

wrapper, marker, home_raw = sys.argv[1:]
home = Path(home_raw)
environment = os.environ.copy()
environment["HOME"] = str(home)
value = "unit-test-fixed-txt-value"
quoted = '"{}"'.format(value).encode("utf-8")
name = "txt-overlay-wrapper.example"
child = "child.txt-overlay-wrapper.example"
other = "txt-overlay-other.example"
cookie_name = "txt-cookie-wrapper.example"
hex_name = "txt-hexcookie-wrapper.example"
common = ["@127.0.0.1", "-p", "9", "+short", "+time=1", "+tries=1"]


def run(label, arguments):
    try:
        result = subprocess.run(
            [wrapper] + arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL: {} timed out".format(label))
    if result.returncode not in {0, 9}:
        raise SystemExit(
            "FAIL: {} rc {} not in {{0, 9}}\nstdout={!r}\nstderr={!r}".format(
                label, result.returncode, result.stdout, result.stderr
            )
        )
    blob = (result.stdout + result.stderr).lower()
    if b"traceback" in blob:
        raise SystemExit("FAIL: {} emitted a traceback".format(label))
    if b"couldn't parse" in blob or b"invalid option" in blob:
        raise SystemExit("FAIL: {} leaked overlay token to real dig".format(label))
    return result


def records():
    path = home / ".cache" / "dig-zcode-wrapper" / "txt.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("version") != 2 or not isinstance(payload.get("records"), dict):
        raise SystemExit("FAIL: txt.json schema is wrong: {!r}".format(payload))
    flat = {}
    for key, item in payload["records"].items():
        if isinstance(item, str):
            flat[key] = item
        elif isinstance(item, dict) and isinstance(item.get("value"), str):
            flat[key] = item["value"]
        else:
            raise SystemExit("FAIL: txt.json record is wrong: {!r}".format(item))
    return flat


help_result = subprocess.run(
    [wrapper, "-h"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=environment,
    timeout=10,
    check=False,
)
help_text = (help_result.stdout + help_result.stderr).decode("utf-8", "replace")
if "+txt=" in help_text or "txt.json" in help_text:
    raise SystemExit("FAIL: wrapper-specific TXT overlay leaked into dig -h")

first = run("set overlay", ["+txt=" + value, "TXT", name] + common)
if quoted not in first.stdout:
    raise SystemExit("FAIL: setting +txt= did not append the overlay")
if records().get(name) != value:
    raise SystemExit("FAIL: txt.json did not persist the overlay: {!r}".format(records()))

second = run("persistent overlay", ["TXT", name] + common)
if quoted not in second.stdout:
    raise SystemExit("FAIL: later TXT lookup did not return the overlay")

typed = run("type filter", ["A", name] + common)
if quoted in typed.stdout:
    raise SystemExit("FAIL: A lookup injected a TXT overlay")

inherited = run("parent inheritance", ["TXT", child] + common)
if quoted not in inherited.stdout:
    raise SystemExit("FAIL: child domain did not inherit parent overlay")

unrelated = run("unrelated domain", ["TXT", other] + common)
if quoted in unrelated.stdout:
    raise SystemExit("FAIL: overlay leaked to an unrelated domain")

deleted = run("delete overlay", ["+txt=", "TXT", name] + common)
if quoted in deleted.stdout:
    raise SystemExit("FAIL: empty +txt= did not delete the overlay")
if name in records():
    raise SystemExit("FAIL: deleted overlay still present in txt.json")

cookie = run("cookie alias", ["+cookie=not-a-hex-cookie", "TXT", cookie_name] + common)
if b'"not-a-hex-cookie"' not in cookie.stdout:
    raise SystemExit("FAIL: non-hex +cookie= alias did not register overlay")
if records().get(cookie_name) != "not-a-hex-cookie":
    raise SystemExit("FAIL: cookie alias did not persist")

# Hexadecimal +cookie= is left for Apple's dig.  macOS DiG 9.10.6 does not
# implement that option, so the real binary may exit 1 with "Invalid option".
# The wrapper must still refuse to persist it as a TXT overlay.
hex_value = "0123456789abcdef"
try:
    hex_cookie = subprocess.run(
        [wrapper, "+cookie=" + hex_value, "TXT", hex_name] + common,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=30,
        check=False,
    )
except subprocess.TimeoutExpired:
    raise SystemExit("FAIL: hex cookie passthrough timed out")
if b"traceback" in (hex_cookie.stdout + hex_cookie.stderr).lower():
    raise SystemExit("FAIL: hex cookie passthrough emitted a traceback")
if ('"' + hex_value + '"').encode("utf-8") in hex_cookie.stdout:
    raise SystemExit("FAIL: hex +cookie= was treated as a TXT overlay")
if hex_name in records():
    raise SystemExit("FAIL: hex +cookie= wrote txt.json")
TXTTEST

printf '%s\n' 'PASS: stateful dig wrapper integration tests'
