"""Unit tests for SPF parsing logic — no network required."""

import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Helpers duplicated from email_suite for isolated testing ──────────────────

def _parse_spf_directives(record):
    """Return (all_directive, mechanisms) from a raw SPF string."""
    import re
    all_match = re.search(r'([+\-?~]?all)\b', record)
    all_d = all_match.group(1) if all_match else None
    mechs = record.split()[1:]  # strip "v=spf1"
    return all_d, mechs


def _classify_all(all_d):
    if all_d in ("+all", "all"):   return "critical"
    if all_d == "-all":            return "strict"
    if all_d == "~all":            return "softfail"
    if all_d == "?all":            return "neutral"
    return "missing"


class TestSPFParsing(unittest.TestCase):

    def test_strict_hardfail(self):
        rec = "v=spf1 include:_spf.google.com -all"
        all_d, _ = _parse_spf_directives(rec)
        self.assertEqual(all_d, "-all")
        self.assertEqual(_classify_all(all_d), "strict")

    def test_softfail(self):
        rec = "v=spf1 include:sendgrid.net ~all"
        all_d, _ = _parse_spf_directives(rec)
        self.assertEqual(all_d, "~all")
        self.assertEqual(_classify_all(all_d), "softfail")

    def test_passall_critical(self):
        rec = "v=spf1 +all"
        all_d, _ = _parse_spf_directives(rec)
        self.assertEqual(all_d, "+all")
        self.assertEqual(_classify_all(all_d), "critical")

    def test_bare_all_critical(self):
        rec = "v=spf1 all"
        all_d, _ = _parse_spf_directives(rec)
        self.assertIn(all_d, ("+all", "all"))
        self.assertEqual(_classify_all(all_d), "critical")

    def test_neutral(self):
        rec = "v=spf1 ip4:1.2.3.4 ?all"
        all_d, _ = _parse_spf_directives(rec)
        self.assertEqual(all_d, "?all")
        self.assertEqual(_classify_all(all_d), "neutral")

    def test_missing_all(self):
        rec = "v=spf1 include:mailgun.org"
        all_d, _ = _parse_spf_directives(rec)
        self.assertIsNone(all_d)
        self.assertEqual(_classify_all(all_d), "missing")

    def test_ip4_mechanism_parsed(self):
        rec = "v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.1 -all"
        _, mechs = _parse_spf_directives(rec)
        ip4_mechs = [m for m in mechs if m.startswith("ip4:")]
        self.assertEqual(len(ip4_mechs), 2)

    def test_include_chain(self):
        rec = "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all"
        _, mechs = _parse_spf_directives(rec)
        includes = [m for m in mechs if m.startswith("include:")]
        self.assertEqual(len(includes), 2)


class TestDMARCParsing(unittest.TestCase):
    """Unit tests for DMARC tag extraction — no network required."""

    def _parse_tags(self, record):
        tags = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip()] = v.strip()
        return tags

    def test_reject_policy(self):
        rec = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        tags = self._parse_tags(rec)
        self.assertEqual(tags.get("p"), "reject")

    def test_quarantine_policy(self):
        rec = "v=DMARC1; p=quarantine; pct=50"
        tags = self._parse_tags(rec)
        self.assertEqual(tags.get("p"), "quarantine")
        self.assertEqual(tags.get("pct"), "50")

    def test_none_policy(self):
        rec = "v=DMARC1; p=none"
        tags = self._parse_tags(rec)
        self.assertEqual(tags.get("p"), "none")

    def test_subdomain_policy(self):
        rec = "v=DMARC1; p=quarantine; sp=reject"
        tags = self._parse_tags(rec)
        self.assertEqual(tags.get("sp"), "reject")

    def test_rua_extracted(self):
        rec = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:ruf@example.com"
        tags = self._parse_tags(rec)
        self.assertIn("mailto:dmarc@example.com", tags.get("rua", ""))

    def test_alignment_strict(self):
        rec = "v=DMARC1; p=reject; adkim=s; aspf=s"
        tags = self._parse_tags(rec)
        self.assertEqual(tags.get("adkim"), "s")
        self.assertEqual(tags.get("aspf"), "s")


class TestHealthScoreGrading(unittest.TestCase):
    """Unit tests for score-to-grade mapping — no network required."""

    def _grade(self, pct):
        if pct >= 90: return "A"
        if pct >= 75: return "B"
        if pct >= 60: return "C"
        if pct >= 45: return "D"
        return "F"

    def test_grade_a(self):
        self.assertEqual(self._grade(100), "A")
        self.assertEqual(self._grade(90),  "A")

    def test_grade_b(self):
        self.assertEqual(self._grade(89), "B")
        self.assertEqual(self._grade(75), "B")

    def test_grade_c(self):
        self.assertEqual(self._grade(74), "C")
        self.assertEqual(self._grade(60), "C")

    def test_grade_d(self):
        self.assertEqual(self._grade(59), "D")
        self.assertEqual(self._grade(45), "D")

    def test_grade_f(self):
        self.assertEqual(self._grade(44), "F")
        self.assertEqual(self._grade(0),  "F")


def _deps_available():
    for pkg in ("dns", "whois", "requests", "rich"):
        try:
            __import__(pkg)
        except ImportError:
            return False
    return True


_DEPS_OK = _deps_available()
skip_no_deps = unittest.skipUnless(_DEPS_OK, "Runtime deps not installed — skipping CLI tests")


@skip_no_deps
class TestCLIParsing(unittest.TestCase):
    """Unit tests for CLI argument parsing — requires runtime deps."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "domainprobe",
            os.path.join(os.path.dirname(__file__), "..", "domainprobe.py"),
        )
        self.mod = importlib.util.module_from_spec(spec)
        with patch("sys.argv", ["domainprobe.py"]):
            spec.loader.exec_module(self.mod)

    def test_diagnose_domain_command(self):
        args = self.mod.build_parser().parse_args(["diagnose-domain", "example.com"])
        self.assertEqual(args.command, "diagnose-domain")
        self.assertEqual(args.domain,  "example.com")
        self.assertEqual(args.format,  "text")
        self.assertEqual(args.fail_on, "never")

    def test_diagnose_domain_json(self):
        args = self.mod.build_parser().parse_args(
            ["diagnose-domain", "example.com", "--format", "json"]
        )
        self.assertEqual(args.format, "json")

    def test_diagnose_domain_fail_on(self):
        args = self.mod.build_parser().parse_args(
            ["diagnose-domain", "example.com", "--fail-on", "high"]
        )
        self.assertEqual(args.fail_on, "high")

    def test_audit_command(self):
        args = self.mod.build_parser().parse_args(["audit", "example.com"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.domain,  "example.com")

    def test_diagnose_email_command(self):
        args = self.mod.build_parser().parse_args(["diagnose-email", "example.com"])
        self.assertEqual(args.command, "diagnose-email")

    def test_no_command_returns_none(self):
        args = self.mod.build_parser().parse_args([])
        self.assertIsNone(args.command)


if __name__ == "__main__":
    unittest.main()
