#!/usr/bin/python3
"""Offline regressions: a local fixture must not impersonate a DNS reply."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "src" / "dig_wrapper.py"
spec = importlib.util.spec_from_file_location("wrapper_evidence", WRAPPER)
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)


def response(status="NXDOMAIN"):
    return (";; Got answer:\n"
            ";; ->>HEADER<<- opcode: QUERY, status: %s, id: 42\n"
            ";; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0\n\n"
            ";; QUESTION SECTION:\n;missing.example.\tIN\tTXT\n\n"
            ";; AUTHORITY SECTION:\nexample.\t60\tIN\tSOA\ta. b. 1 2 3 4 5\n\n"
            ";; MSG SIZE  rcvd: 100\n" % status).encode("ascii")


class EvidenceTests(unittest.TestCase):
    def test_network_message_is_an_unchanged_prefix(self):
        for status in ("NXDOMAIN", "NOERROR", "SERVFAIL", "REFUSED"):
            with self.subTest(status=status):
                raw = response(status)
                out = wrapper.merge_txt_overlay(
                    raw, ['missing.example.\t600\tIN\tTXT\t"local-value"'], False)
                self.assertEqual(out[:len(raw)], raw)
                self.assertIn(b'"local-value"', out[len(raw):])
                self.assertNotIn(b"LOCAL TEST DATA", out)
                self.assertNotIn(b";; ANSWER SECTION:", out[len(raw):])
                self.assertEqual(out.count(b"MSG SIZE  rcvd:"), 1)

    def test_batch_does_not_rewrite_or_duplicate_network_answers(self):
        raw = response() + response("NOERROR")
        local = 'missing.example.\t600\tIN\tTXT\t"local-value"'
        out = wrapper.merge_txt_overlay(raw, [local], False)
        self.assertTrue(out.startswith(raw))
        self.assertEqual(out.count(b'"local-value"'), 1)

    def test_absent_overlay_is_byte_transparent(self):
        for raw in (b"", response(), b"\xff\xfe no final newline"):
            self.assertEqual(wrapper.merge_txt_overlay(raw, [], False), raw)

    def test_short_output_remains_usable_for_local_tests(self):
        self.assertEqual(wrapper.merge_txt_overlay(b'"public"\n', ['"local"'], True),
                         b'"public"\n"local"\n')

    def test_timeout_is_not_rendered_as_a_network_success(self):
        raw = b";; connection timed out; no servers could be reached\n"
        out = wrapper.merge_txt_overlay(raw, ['"local"'], False)
        self.assertTrue(out.startswith(raw))
        self.assertIn(b'"local"', out)
        self.assertNotIn(b"LOCAL TEST DATA", out)
        self.assertNotIn(b"status: NOERROR", out)

    def test_txt_control_bytes_cannot_forge_sections(self):
        rendered = wrapper.format_txt_string('one\n;; ANSWER SECTION:\x1b[2J\r"\\two')
        self.assertNotIn("\n", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("\\010", rendered)
        self.assertIn("\\027", rendered)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dig-evidence-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / ".cache").mkdir(mode=0o700)
        self.backend = self.home / "fake_backend.py"
        self.backend.write_text(
            "#!/usr/bin/python3\nimport sys\n"
            "if '+badoption' in sys.argv: sys.exit(1)\n"
            "if '+timeout' in sys.argv:\n"
            " print(';; connection timed out; no servers could be reached'); sys.exit(9)\n"
            "if '+short' not in sys.argv: sys.stdout.buffer.write(%r)\n" % response())
        self.backend.chmod(0o700)

    def run_wrapper(self, *args):
        runner = ("import importlib.util,sys; "
                  "s=importlib.util.spec_from_file_location('test_wrapper',sys.argv[1]); "
                  "w=importlib.util.module_from_spec(s); s.loader.exec_module(w); "
                  "w.REAL_DIG=sys.argv[2]; sys.argv=[sys.argv[1]]+sys.argv[3:]; "
                  "sys.exit(w.main())")
        return subprocess.run(
            [sys.executable, "-c", runner, str(WRAPPER), str(self.backend)] + list(args),
            env=dict(os.environ, HOME=str(self.home)), capture_output=True, timeout=5)

    def test_full_output_preserves_nxdomain_and_appends_overlay(self):
        r = self.run_wrapper("+txt=unit-local-only", "TXT", "missing.example")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith(response()))
        self.assertIn(b'"unit-local-only"', r.stdout)
        self.assertNotIn(b"LOCAL TEST DATA", r.stdout)
        self.assertNotIn(b"not a DNS answer", r.stderr)
        self.assertNotIn(b"unit-local-only", r.stderr)

    def test_pinned_txt_is_stable_across_lookups(self):
        for n in range(3):
            args = (["+txt=unit-local-only"] if n == 0 else [])
            r = self.run_wrapper(*(args + ["TXT", "missing.example", "+short"]))
            self.assertEqual(r.returncode, 0)
            self.assertEqual(r.stdout, b'"unit-local-only"\n')
            self.assertNotIn(b"not a DNS answer", r.stderr)

    def test_rejected_query_does_not_persist_overlay_or_counts(self):
        r = self.run_wrapper("+txt=must-not-persist", "TXT", "missing.example", "+badoption")
        self.assertEqual(r.returncode, 1)
        self.assertFalse((self.home / ".cache/dig-zcode-wrapper").exists())

    def test_timeout_retains_real_exit_status(self):
        r = self.run_wrapper("+txt=unit-local-only", "TXT", "missing.example", "+timeout")
        self.assertEqual(r.returncode, 9)
        self.assertIn(b"timed out", r.stdout)
        self.assertIn(b'"unit-local-only"', r.stdout)
        self.assertNotIn(b"LOCAL TEST DATA", r.stdout)
        self.assertNotIn(b"not a DNS answer", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
