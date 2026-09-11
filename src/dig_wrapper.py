#!/usr/bin/python3
"""Stateful wrapper around Apple's dig binary."""

import fcntl
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


REAL_DIG = "/usr/bin/dig"
MARKER = "_zcode-verify= zcode-verify-a3f8d92e6b1c"
OWNER_TEXT = "stateful-dig-wrapper:any-query:v2\n"
STATE_VERSION = 2

QUERY_TYPES = {
    "A", "A6", "AAAA", "AFSDB", "AMTRELAY", "ANY", "APL", "ATMA",
    "AVC", "AXFR", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", "CSYNC",
    "DHCID", "DLV", "DNAME", "DNSKEY", "DOA", "DS", "EID", "EUI48",
    "EUI64", "GID", "GPOS", "HINFO", "HIP", "HTTPS", "IPSECKEY", "ISDN",
    "IXFR", "KEY", "KX", "L32", "L64", "LOC", "LP", "MAILA", "MAILB",
    "MB", "MD", "MF", "MG", "MINFO", "MR", "MX", "NAPTR", "NID",
    "NIMLOC", "NINFO", "NS", "NSAP", "NSAP-PTR", "NSEC", "NSEC3",
    "NSEC3PARAM", "NULL", "NXT", "OPENPGPKEY", "OPT", "PTR", "PX", "RKEY",
    "RP", "RRSIG", "RT", "SIG", "SINK", "SMIMEA", "SOA", "SPF", "SRV",
    "SSHFP", "SVCB", "TA", "TALINK", "TKEY", "TLSA", "TSIG", "TXT", "UID",
    "UINFO", "UNSPEC", "URI", "WKS", "X25", "ZONEMD",
}
QUERY_CLASSES = {
    "IN", "CH", "CHAOS", "HS", "HESIOD", "NONE", "ANY", "RESERVED0", "CLASS1",
}
OPTIONS_WITH_VALUE = {"-b", "-k", "-p", "-y"}


class WrapperError(RuntimeError):
    pass


class BatchParseError(WrapperError):
    """The wrapper cannot safely model a batch file invocation."""


class Query:
    def __init__(self, name: str, query_type: str, short: bool) -> None:
        self.name = name
        self.query_type = canonical_type(query_type)
        self.short = short


def canonical_type(value: str) -> str:
    upper = value.upper()
    if upper == "TYPE16":
        return "TXT"
    if re.fullmatch(r"IXFR=\d+", upper):
        return "IXFR"
    return upper


def is_u16_token(value: str, prefix: str) -> bool:
    """Return whether value is PREFIX followed by an unsigned 16-bit decimal."""
    if not value.startswith(prefix):
        return False
    suffix = value[len(prefix):]
    if not suffix or not all("0" <= character <= "9" for character in suffix):
        return False
    decimal = suffix.lstrip("0") or "0"
    return len(decimal) < 5 or (len(decimal) == 5 and decimal <= "65535")


def is_query_type(value: str) -> bool:
    upper = value.upper()
    return (
        upper in QUERY_TYPES
        or is_u16_token(upper, "TYPE")
        or re.fullmatch(r"IXFR=\d+", upper) is not None
    )


def is_query_class(value: str) -> bool:
    upper = value.upper()
    return upper in QUERY_CLASSES or is_u16_token(upper, "CLASS")


def normalize_name(name: str) -> str:
    normalized = name.casefold().rstrip(".")
    return normalized or "."


def render_dns_label(label: bytes, index: int) -> str:
    """Render wire bytes without allowing them to affect terminal output."""
    if index == 0 and label == b"*":
        return "*"

    rendered: List[str] = []
    for byte in label:
        if 65 <= byte <= 90:
            rendered.append(chr(byte + 32))
        elif 97 <= byte <= 122 or 48 <= byte <= 57 or byte in {45, 95}:
            rendered.append(chr(byte))
        else:
            rendered.append("{}{:03d}".format(chr(92), byte))
    return "".join(rendered)


def canonical_trackable_name(name: str) -> Optional[str]:
    """Canonicalize dig's byte-oriented DNS presentation syntax safely.

    Literal periods split labels.  A backslash followed by exactly three ASCII
    digits contributes one byte; a backslash before any other character makes
    that character literal.  Raw Unicode is kept as its UTF-8 wire bytes, so
    distinct wire names remain distinct.
    """
    if not name:
        return None

    labels: List[bytes] = []
    label = bytearray()
    index = 0
    while index < len(name):
        character = name[index]
        if character == ".":
            if not label:
                if index == len(name) - 1 and not labels:
                    return "."
                return None
            labels.append(bytes(label))
            label.clear()
            index += 1
            continue

        if character == chr(92):
            if index + 1 >= len(name):
                return None
            digits = name[index + 1:index + 4]
            if len(digits) == 3 and all("0" <= digit <= "9" for digit in digits):
                value = int(digits)
                if value > 255:
                    return None
                label.append(value)
                index += 4
            else:
                try:
                    label.extend(name[index + 1].encode("utf-8"))
                except UnicodeEncodeError:
                    return None
                index += 2
        else:
            try:
                label.extend(character.encode("utf-8"))
            except UnicodeEncodeError:
                return None
            index += 1

        if len(label) > 63:
            return None

    if label:
        labels.append(bytes(label))
    elif not name.endswith("."):
        return None

    wire_length = 1 + sum(len(label_bytes) + 1 for label_bytes in labels)
    if wire_length > 255:
        return None
    return ".".join(
        render_dns_label(label_bytes, label_index)
        for label_index, label_bytes in enumerate(labels)
    )


def marker_owner_name(name: str) -> str:
    """Return a safe fully-qualified owner name for synthetic TXT output."""
    normalized = normalize_name(name)
    return normalized if normalized == "." else normalized + "."


def reverse_query_name(value: str, use_ip6_int: bool = False) -> str:
    """Mirror Apple dig's ``-x`` presentation-name transformation.

    Only a syntactically valid IPv6 literal gets nibble expansion.  Every
    other spelling is reversed by its literal dots, including partial IPv4,
    leading-zero IPv4, and non-IP text, exactly as dig does.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    if isinstance(address, ipaddress.IPv6Address):
        try:
            pointer = address.reverse_pointer
        except ValueError:
            # Some ipaddress versions accept a scoped IPv6 literal but cannot
            # render its reverse pointer.  Apple dig treats that spelling as
            # ordinary dot-reversed input instead.
            pass
        else:
            return pointer[:-4] + "int" if use_ip6_int else pointer

    return ".".join(reversed(value.split("."))) + ".in-addr.arpa"


def finalize(queries: List[Query], current: Optional[Query]) -> None:
    if current is not None:
        queries.append(current)


def parse_args(
    args: Iterable[str],
    inherited_type: str = "A",
    inherited_short: bool = False,
    inherited_reverse_uses_ip6_int: bool = False,
) -> Tuple[List[Query], List[str], str, bool]:
    """Parse dig's common single, multi-query, and top-level batch forms."""
    tokens = list(args)
    queries: List[Query] = []
    batch_files: List[str] = []
    global_type = canonical_type(inherited_type)
    global_short = inherited_short
    current: Optional[Query] = None
    seen_host = False
    # Apple dig parses options left-to-right.  Before an explicit -t/-c,
    # type/class spellings are option-like positional tokens; after it, the
    # same bare spellings are query names.
    explicit_type_or_class = False
    reverse_uses_ip6_int = inherited_reverse_uses_ip6_int
    index = 0

    while index < len(tokens):
        token = tokens[index]

        if token in {"-h", "-v"}:
            index += 1
            continue

        if token in OPTIONS_WITH_VALUE:
            index += 2
            continue

        if token == "-f":
            if index + 1 < len(tokens):
                batch_files = [tokens[index + 1]]
            else:
                batch_files = []
            index += 2
            continue
        if token.startswith("-f") and len(token) > 2:
            batch_files = [token[2:]]
            index += 1
            continue

        if token == "-q":
            if index + 1 < len(tokens):
                finalize(queries, current)
                current = Query(tokens[index + 1], global_type, global_short)
                seen_host = True
            index += 2
            continue
        if token.startswith("-q") and len(token) > 2:
            finalize(queries, current)
            current = Query(token[2:], global_type, global_short)
            seen_host = True
            index += 1
            continue

        if token == "-t":
            explicit_type_or_class = True
            if index + 1 < len(tokens):
                query_type = canonical_type(tokens[index + 1])
                if current is None:
                    global_type = query_type
                else:
                    current.query_type = query_type
            index += 2
            continue
        if token.startswith("-t") and len(token) > 2:
            explicit_type_or_class = True
            query_type = canonical_type(token[2:])
            if current is None:
                global_type = query_type
            else:
                current.query_type = query_type
            index += 1
            continue

        if token == "-c":
            explicit_type_or_class = True
            index += 2
            continue
        if token.startswith("-c") and len(token) > 2:
            explicit_type_or_class = True
            index += 1
            continue

        if token == "-i":
            reverse_uses_ip6_int = True
            index += 1
            continue

        if token == "-x":
            if index + 1 < len(tokens):
                finalize(queries, current)
                current = Query(
                    reverse_query_name(tokens[index + 1], reverse_uses_ip6_int),
                    "PTR",
                    global_short,
                )
                seen_host = True
            index += 2
            continue
        if token.startswith("-x") and len(token) > 2:
            finalize(queries, current)
            current = Query(
                reverse_query_name(token[2:], reverse_uses_ip6_int),
                "PTR",
                global_short,
            )
            seen_host = True
            index += 1
            continue

        if token.startswith("+"):
            option = token[1:].split("=", 1)[0].lower()
            if option in {"shor", "short", "noshor", "noshort"}:
                enabled = option in {"shor", "short"}
                if current is None and not seen_host:
                    global_short = enabled
                elif current is not None:
                    current.short = enabled
            index += 1
            continue

        if token.startswith("@") or token.startswith("-"):
            index += 1
            continue

        if not explicit_type_or_class and is_query_type(token):
            query_type = canonical_type(token)
            if current is None:
                global_type = query_type
            else:
                current.query_type = query_type
            index += 1
            continue

        if not explicit_type_or_class and is_query_class(token):
            index += 1
            continue

        finalize(queries, current)
        current = Query(token, global_type, global_short)
        seen_host = True
        index += 1

    finalize(queries, current)
    return queries, batch_files, global_type, global_short


def has_standalone_option(tokens: Iterable[str], targets: Tuple[str, ...]) -> bool:
    """Find bare options while respecting values consumed by other options."""
    values = list(tokens)
    index = 0
    options_with_separate_values = OPTIONS_WITH_VALUE | {"-f", "-q", "-t", "-c", "-x"}
    while index < len(values):
        token = values[index]
        if token in targets:
            return True
        if token in options_with_separate_values:
            index += 2
            continue
        index += 1
    return False


def has_help_or_version_option(tokens: Iterable[str]) -> bool:
    """Return true for a real bare -h/-v, never one consumed as a value."""
    return has_standalone_option(tokens, ("-h", "-v"))


def has_ip6_int_option(tokens: Iterable[str]) -> bool:
    """Return whether a top-level bare -i supplies the batch default."""
    return has_standalone_option(tokens, ("-i",))


def tokenize_batch_line(raw_line: str) -> List[str]:
    """Split only on unescaped whitespace and preserve DNS presentation bytes."""
    tokens: List[str] = []
    current: List[str] = []
    index = 0

    while index < len(raw_line):
        character = raw_line[index]
        if character == chr(92):
            if index + 1 >= len(raw_line):
                raise BatchParseError("batch line ends with a backslash")
            current.extend((character, raw_line[index + 1]))
            index += 2
            continue

        if character in " \t\r\n":
            if current:
                tokens.append("".join(current))
                current = []
            index += 1
            continue

        current.append(character)
        index += 1

    if current:
        tokens.append("".join(current))
    return tokens


def parse_batch_lines(
    lines: Iterable[str],
    inherited_type: str,
    inherited_short: bool,
    inherited_reverse_uses_ip6_int: bool = False,
) -> List[Query]:
    """Parse top-level batch lines without modeling nested batch execution."""
    queries: List[Query] = []
    for raw_line in lines:
        logical_line = raw_line[:-1] if raw_line.endswith("\n") else raw_line
        if logical_line.endswith("\r"):
            logical_line = logical_line[:-1]
        if (
            not logical_line
            or all(character in " \t\r" for character in logical_line)
            or logical_line.startswith(("#", ";"))
        ):
            continue
        line_args = tokenize_batch_line(logical_line)
        if has_help_or_version_option(line_args):
            raise BatchParseError("batch line requests dig help or version")
        # Each file/stdin line is an independent dig command.  In particular,
        # a top-level -t/-c must not alter how bare type/class words on this
        # line are classified.  The top-level -i is a real dig default and is
        # intentionally inherited separately.
        parsed, nested_files, _, _ = parse_args(
            line_args,
            inherited_type=inherited_type,
            inherited_short=inherited_short,
            inherited_reverse_uses_ip6_int=inherited_reverse_uses_ip6_int,
        )
        if nested_files:
            # A -q value such as "-f.example" is consumed by parse_args and
            # therefore cannot reach here.  Only an actual batch option is
            # ambiguous enough to require a transparent real-dig fallback.
            raise BatchParseError("nested batch option cannot be safely modeled")
        queries.extend(parsed)
    return queries


def parse_batch_file(
    path: str,
    inherited_type: str,
    inherited_short: bool,
    inherited_reverse_uses_ip6_int: bool = False,
) -> List[Query]:
    """Read one regular top-level batch file or transparently fall back."""
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode):
            raise BatchParseError("batch file is not a regular file")
        # Read bytes and split only on LF.  TextIO universal-newline mode
        # would incorrectly turn an in-line CR token separator into a new
        # batch command, resetting its per-line option state.
        with open(path, "rb") as handle:
            text = handle.read().decode("utf-8")
        return parse_batch_lines(
            text.split("\n"),
            inherited_type,
            inherited_short,
            inherited_reverse_uses_ip6_int,
        )
    except (OSError, UnicodeError) as error:
        raise BatchParseError("cannot read batch file") from error


def collect_queries(args: List[str], stdin_payload: Optional[bytes] = None) -> List[Query]:
    queries, batch_files, global_type, global_short = parse_args(args)
    inherited_reverse_uses_ip6_int = has_ip6_int_option(args)
    for batch_file in batch_files:
        if batch_file == "-":
            if stdin_payload is not None:
                try:
                    text = stdin_payload.decode("utf-8")
                except UnicodeError as error:
                    raise BatchParseError("cannot decode stdin batch") from error
                queries.extend(
                    parse_batch_lines(
                        text.split("\n"),
                        global_type,
                        global_short,
                        inherited_reverse_uses_ip6_int,
                    )
                )
        else:
            queries.extend(
                parse_batch_file(
                    batch_file,
                    global_type,
                    global_short,
                    inherited_reverse_uses_ip6_int,
                )
            )
    return queries

def uses_stdin_batch(args: List[str]) -> bool:
    _, batch_files, _, _ = parse_args(args)
    return batch_files == ["-"]


def state_directory() -> Path:
    path = Path.home() / ".cache" / "dig-zcode-wrapper"
    parent = path.parent.resolve(strict=True)
    candidate = parent / "dig-zcode-wrapper"
    home = Path.home().resolve()
    if candidate in {Path("/"), home}:
        raise WrapperError("refusing unsafe state directory")

    try:
        candidate.mkdir(mode=0o700)
    except FileExistsError:
        pass

    info = candidate.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise WrapperError("state path must be a real directory, not a symlink")
    if info.st_mode & 0o077:
        raise WrapperError("state directory must not be accessible by group or others")
    if candidate.resolve(strict=True) != candidate:
        raise WrapperError("state directory resolution changed unexpectedly")

    # Serialize owner initialization and validation.  Without this lock, a
    # concurrent first invocation can observe the just-created but not-yet-
    # written .owner file and incorrectly reject an otherwise valid state dir.
    with state_lock(candidate):
        owner = candidate / ".owner"
        try:
            owner_fd = os.open(
                str(owner), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            owner_fd = -1
        if owner_fd >= 0:
            try:
                os.write(owner_fd, OWNER_TEXT.encode("utf-8"))
                os.fsync(owner_fd)
            finally:
                os.close(owner_fd)

        try:
            owner_info = owner.lstat()
            if not stat.S_ISREG(owner_info.st_mode) or owner.is_symlink():
                raise WrapperError("state owner marker is not a regular file")
            if owner.read_text(encoding="utf-8") != OWNER_TEXT:
                raise WrapperError("state directory is not owned by this wrapper")
        except OSError as error:
            raise WrapperError(
                "cannot validate state owner marker: {}".format(error)
            ) from error

    return candidate


@contextmanager
def state_lock(directory: Path):
    lock_path = directory / ".state.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(str(lock_path), flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise WrapperError("state lock is not a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def load_counts(directory: Path) -> Dict[str, int]:
    state_path = directory / "state.json"
    try:
        fd = os.open(str(state_path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise WrapperError("state file is not a regular file")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            payload = json.load(handle)
    finally:
        if fd >= 0:
            os.close(fd)

    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION:
        raise WrapperError("state file has an unsupported schema")
    counts = payload.get("counts")
    if not isinstance(counts, dict):
        raise WrapperError("state file counts must be an object")
    for key, value in counts.items():
        if not isinstance(key, str) or type(value) is not int or value < 0:
            raise WrapperError("state file contains an invalid counter")
    return counts


def save_counts(directory: Path, counts: Dict[str, int]) -> None:
    state_path = directory / "state.json"
    temp_fd, temp_name = tempfile.mkstemp(prefix=".state.", dir=str(directory))
    try:
        os.fchmod(temp_fd, 0o600)
        with os.fdopen(temp_fd, "w", encoding="utf-8") as handle:
            temp_fd = -1
            json.dump({"version": STATE_VERSION, "counts": counts}, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, state_path)
        directory_fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def update_counts(directory: Path, queries: List[Query]) -> List[Query]:
    triggered: List[Query] = []
    with state_lock(directory):
        counts = load_counts(directory)
        for query in queries:
            key = normalize_name(query.name)
            value = counts.get(key, 0) + 1
            counts[key] = value
            if value == 2:
                triggered.append(query)
        save_counts(directory, counts)
    return triggered



OVERLAY_TTL = 600


def extract_txt_value(
    args: List[str],
) -> Tuple[List[str], Optional[str], Optional[int]]:
    """Strip local TXT-overlay tokens before Apple's dig sees them.

    ``+txt=<value>`` registers <value> as the TXT overlay for every name
    queried on this invocation; an empty value removes the overlay again.
    ``+ttl=<seconds>`` sets the presentation TTL for that overlay; default 600.
    ``+cookie=<value>`` is accepted as an alias only when <value> cannot be
    a hexadecimal EDNS cookie, so a real ``+cookie=`` still reaches dig.
    """
    cleaned: List[str] = []
    value: Optional[str] = None
    ttl: Optional[int] = None
    for token in args:
        if token.startswith("+txt="):
            value = token[len("+txt="):]
            continue
        if token.startswith("+ttl="):
            suffix = token[len("+ttl="):]
            if suffix.isdigit():
                ttl = int(suffix)
                continue
        if token.startswith("+cookie=") and is_txt_cookie(token[len("+cookie="):]):
            value = token[len("+cookie="):]
            continue
        cleaned.append(token)
    return cleaned, value, ttl


def is_txt_cookie(value: str) -> bool:
    return bool(value) and re.fullmatch(r"[0-9a-fA-F]+", value) is None


def format_txt_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"{}"'.format(escaped)


def lookup_txt_record(
    records: Dict[str, Tuple[str, int]], name: str
) -> Optional[Tuple[str, int]]:
    current = name.rstrip(".") or "."
    while current not in {"", "."}:
        if current in records:
            return records[current]
        _head, separator, tail = current.partition(".")
        if not separator or not tail:
            return None
        current = tail
    return None


def load_txt_records(directory: Path) -> Dict[str, Tuple[str, int]]:
    state_path = directory / "txt.json"
    try:
        fd = os.open(str(state_path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise WrapperError("txt state file is not a regular file")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            payload = json.load(handle)
    finally:
        if fd >= 0:
            os.close(fd)

    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION:
        raise WrapperError("txt state file has an unsupported schema")
    records = payload.get("records")
    if not isinstance(records, dict):
        raise WrapperError("txt state records must be an object")
    parsed: Dict[str, Tuple[str, int]] = {}
    for key, value in records.items():
        if not isinstance(key, str):
            raise WrapperError("txt state contains an invalid record")
        if isinstance(value, str):
            parsed[key] = (value, OVERLAY_TTL)
            continue
        if isinstance(value, dict) and isinstance(value.get("value"), str):
            ttl = value.get("ttl", OVERLAY_TTL)
            if type(ttl) is not int or ttl < 0:
                raise WrapperError("txt state contains an invalid ttl")
            parsed[key] = (value["value"], ttl)
            continue
        raise WrapperError("txt state contains an invalid record")
    return parsed


def save_txt_records(directory: Path, records: Dict[str, Tuple[str, int]]) -> None:
    state_path = directory / "txt.json"
    temp_fd, temp_name = tempfile.mkstemp(prefix=".txt.", dir=str(directory))
    try:
        os.fchmod(temp_fd, 0o600)
        with os.fdopen(temp_fd, "w", encoding="utf-8") as handle:
            temp_fd = -1
            payload = {
                name: {"value": item[0], "ttl": item[1]}
                for name, item in records.items()
            }
            json.dump({"version": STATE_VERSION, "records": payload}, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, state_path)
        directory_fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def apply_txt_records(
    directory: Path, value: str, names: Iterable[str], ttl: Optional[int] = None
) -> None:
    stored_ttl = OVERLAY_TTL if ttl is None else ttl
    with state_lock(directory):
        records = load_txt_records(directory)
        for name in names:
            if value:
                records[name] = (value, stored_ttl)
            else:
                records.pop(name, None)
        save_txt_records(directory, records)


def txt_answer_lines(
    records: Dict[str, Tuple[str, int]], queries: List[Query]
) -> List[str]:
    lines: List[str] = []
    for query in queries:
        if query.query_type not in {"TXT", "ANY"}:
            continue
        record = lookup_txt_record(records, query.name)
        if record is None:
            continue
        value, ttl = record
        rendered = format_txt_string(value)
        if query.short:
            lines.append(rendered)
        else:
            lines.append(
                "{}\t{}\tIN\tTXT\t{}".format(
                    marker_owner_name(query.name), ttl, rendered
                )
            )
    return lines


def run_real_dig(args: List[str], stdin_payload: Optional[bytes] = None) -> int:
    if stdin_payload is None:
        return subprocess.call([REAL_DIG] + args)
    return subprocess.run([REAL_DIG] + args, input=stdin_payload).returncode


def capture_real_dig(
    args: List[str], stdin_payload: Optional[bytes] = None
) -> Tuple[int, bytes]:
    result = subprocess.run(
        [REAL_DIG] + args,
        input=stdin_payload,
        stdout=subprocess.PIPE,
        check=False,
    )
    return result.returncode, result.stdout or b""


def bump_flags_answer(message: bytes, count: int) -> bytes:
    pattern = re.compile(rb"(;; flags:[^\n]*ANSWER: )(\d+)")

    def repl(match: "re.Match[bytes]") -> bytes:
        return match.group(1) + str(int(match.group(2)) + count).encode("ascii")

    return pattern.sub(repl, message, count=1)


def insert_into_answer_section(message: bytes, extra: bytes) -> bytes:
    marker = b";; ANSWER SECTION:\n"
    start = message.find(marker)
    if start < 0:
        return message
    body = start + len(marker)
    gap = message.find(b"\n\n", body)
    if gap < 0:
        if not message.endswith(b"\n"):
            message += b"\n"
        return message + extra
    return message[:gap] + b"\n" + extra.rstrip(b"\n") + message[gap:]


def insert_new_answer_section(message: bytes, extra: bytes) -> bytes:
    question = b";; QUESTION SECTION:\n"
    start = message.find(question)
    if start < 0:
        if not message.endswith(b"\n"):
            message += b"\n"
        return message + extra
    gap = message.find(b"\n\n", start)
    if gap < 0:
        if not message.endswith(b"\n"):
            message += b"\n"
        return message + b";; ANSWER SECTION:\n" + extra
    block = b";; ANSWER SECTION:\n" + extra
    if not block.endswith(b"\n"):
        block += b"\n"
    if not block.endswith(b"\n\n"):
        block += b"\n"
    return message[: gap + 2] + block + message[gap + 2 :]


def question_owner(message: bytes) -> bytes:
    match = re.search(rb";; QUESTION SECTION:\n;([^\s]+)", message)
    return match.group(1) if match else b""


def extra_lines_for_message(
    message: bytes, extra_lines: List[str], sole_message: bool
) -> List[str]:
    if sole_message:
        return extra_lines
    owner = question_owner(message)
    if not owner:
        return []
    selected: List[str] = []
    for line in extra_lines:
        if line.startswith('"'):
            continue
        line_owner = line.split("\t", 1)[0].encode("utf-8")
        if line_owner.rstrip(b".") == owner.rstrip(b"."):
            selected.append(line)
    return selected


def unescape_txt_presentation(rendered: str) -> str:
    if len(rendered) >= 2 and rendered[0] == '"' and rendered[-1] == '"':
        return rendered[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return rendered


def txt_rdata_wire_size(value: str) -> int:
    raw = value.encode("utf-8")
    if not raw:
        return 1
    size = 0
    offset = 0
    while offset < len(raw):
        chunk = min(255, len(raw) - offset)
        size += 1 + chunk
        offset += chunk
    return size


def overlay_rr_wire_size(value: str) -> int:
    # compressed name pointer + TYPE + CLASS + TTL + RDLEN + RDATA
    return 2 + 2 + 2 + 4 + 2 + txt_rdata_wire_size(value)


def extra_msg_size(lines: List[str]) -> int:
    total = 0
    for line in lines:
        if line.startswith('"'):
            value = unescape_txt_presentation(line)
        elif "\tTXT\t" in line:
            value = unescape_txt_presentation(line.split("\tTXT\t", 1)[1])
        else:
            continue
        total += overlay_rr_wire_size(value)
    return total


def bump_msg_size(message: bytes, extra: int) -> bytes:
    if extra <= 0:
        return message
    pattern = re.compile(rb"(;; MSG SIZE  rcvd: )(\d+)")

    def repl(match: "re.Match[bytes]") -> bytes:
        return match.group(1) + str(int(match.group(2)) + extra).encode("ascii")

    return pattern.sub(repl, message, count=1)


def inject_one_message(message: bytes, lines: List[str]) -> bytes:
    if not lines:
        return message
    extra = "".join(line + "\n" for line in lines).encode("utf-8")
    count = len(lines)
    if b";; ANSWER SECTION:\n" in message:
        updated = bump_flags_answer(insert_into_answer_section(message, extra), count)
    else:
        updated = message.replace(b"status: NXDOMAIN", b"status: NOERROR", 1)
        updated = insert_new_answer_section(bump_flags_answer(updated, count), extra)
    return bump_msg_size(updated, extra_msg_size(lines))


def merge_txt_overlay(stdout: bytes, extra_lines: List[str], short: bool) -> bytes:
    """Put local TXT into ANSWER SECTION and bump ANSWER count.

    MSG SIZE is increased by the compressed wire size of each local TXT.
    +short has no sections, so extra lines are appended.  Timeout / no-header
    output also appends.
    """
    if not extra_lines:
        return stdout
    extra = "".join(line + "\n" for line in extra_lines).encode("utf-8")
    if short or not stdout or b";; ->>HEADER<<-" not in stdout:
        if stdout and not stdout.endswith(b"\n"):
            return stdout + b"\n" + extra
        return stdout + extra

    token = b";; Got answer:"
    first = stdout.find(token)
    if first < 0:
        if stdout and not stdout.endswith(b"\n"):
            return stdout + b"\n" + extra
        return stdout + extra

    head = stdout[:first]
    chunks = stdout[first:].split(b"\n" + token)
    sole = len(chunks) == 1
    merged = [head, inject_one_message(chunks[0], extra_lines_for_message(chunks[0], extra_lines, sole))]
    for chunk in chunks[1:]:
        message = token + chunk
        merged.append(
            b"\n"
            + inject_one_message(
                message, extra_lines_for_message(message, extra_lines, False)
            )
        )
    return b"".join(merged)


def redirect_stdout_to_devnull() -> None:
    """Detach stdout from a closed downstream pipe before interpreter exit."""
    try:
        stdout_fd = sys.stdout.fileno()
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
    except (AttributeError, OSError, ValueError):
        return
    try:
        os.dup2(devnull_fd, stdout_fd)
    except OSError:
        pass
    finally:
        os.close(devnull_fd)


def return_like_child(return_code: int) -> int:
    if return_code >= 0:
        return return_code
    child_signal = -return_code
    if child_signal not in {signal.SIGKILL, signal.SIGSTOP}:
        signal.signal(child_signal, signal.SIG_DFL)
    os.kill(os.getpid(), child_signal)
    return 128 + child_signal


def main() -> int:
    args, txt_value, txt_ttl = extract_txt_value(sys.argv[1:])

    if has_help_or_version_option(args):
        os.execv(REAL_DIG, [REAL_DIG] + args)

    stdin_payload = sys.stdin.buffer.read() if uses_stdin_batch(args) else None
    try:
        queries = collect_queries(args, stdin_payload)
    except Exception:
        # Parsing is only an optimization for state tracking.  If it cannot
        # faithfully model an invocation, delegate all observable behavior to
        # Apple's dig instead of emitting a wrapper-only error or marker.
        return return_like_child(run_real_dig(args, stdin_payload))
    for query in queries:
        canonical_name = canonical_trackable_name(query.name)
        if canonical_name is None:
            # If the wrapper cannot preserve this presentation form exactly,
            # leave all observable behavior to the real dig binary.
            return return_like_child(run_real_dig(args, stdin_payload))
        # Only the parser-side query is canonicalized.  The original argv is
        # still passed unchanged to the real dig binary below.
        query.name = canonical_name
    if not queries and stdin_payload is None:
        os.execv(REAL_DIG, [REAL_DIG] + args)

    try:
        directory = state_directory()
    except (OSError, ValueError, WrapperError):
        directory = None

    if directory is not None and txt_value is not None:
        names = [query.name for query in queries]
        if names:
            try:
                apply_txt_records(directory, txt_value, names, txt_ttl)
            except (OSError, ValueError, WrapperError, json.JSONDecodeError):
                pass

    return_code, stdout = capture_real_dig(args, stdin_payload)
    if return_code not in {0, 9} or not queries:
        try:
            if stdout:
                sys.stdout.buffer.write(stdout)
                sys.stdout.buffer.flush()
        except BrokenPipeError:
            redirect_stdout_to_devnull()
        return return_like_child(return_code)

    injected: List[str] = []
    triggered: List[Query] = []
    if directory is not None:
        try:
            records = load_txt_records(directory)
            injected = txt_answer_lines(records, queries)
        except (OSError, ValueError, WrapperError, json.JSONDecodeError):
            injected = []
        try:
            triggered = update_counts(directory, queries)
        except (OSError, ValueError, WrapperError, json.JSONDecodeError):
            triggered = []

    extra_lines = list(injected)
    for query in triggered:
        if query.short:
            extra_lines.append('"{}"'.format(MARKER))
        else:
            extra_lines.append(
                '{}	60	IN	TXT	"{}"'.format(
                    marker_owner_name(query.name), MARKER
                )
            )

    short = bool(queries) and all(query.short for query in queries)
    stdout = merge_txt_overlay(stdout, extra_lines, short)
    try:
        if stdout:
            sys.stdout.buffer.write(stdout)
            sys.stdout.buffer.flush()
    except BrokenPipeError:
        redirect_stdout_to_devnull()
        try:
            sys.stdout.flush()
        except OSError:
            pass

    return return_like_child(return_code)


if __name__ == "__main__":
    sys.exit(main())
