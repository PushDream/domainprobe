"""
Smoke tests — hit real DNS / network.
Skipped automatically when network is unavailable.

Run:  python -m pytest tests/smoke_test.py -v
"""

import sys
import os
import socket
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Network availability guard ────────────────────────────────────────────────
def _network_available():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

NETWORK = _network_available()
skip_no_network = unittest.skipUnless(NETWORK, "No network — skipping smoke tests")


# ── Smoke: DNS Core ───────────────────────────────────────────────────────────
@skip_no_network
class TestDNSCoreSmoke(unittest.TestCase):

    def test_resolve_safe_a_record(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("google.com", "A")
        self.assertEqual(status, "ok")
        self.assertTrue(len(vals) > 0)
        self.assertGreater(ttl, 0)

    def test_resolve_safe_mx(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("google.com", "MX")
        self.assertEqual(status, "ok")
        self.assertTrue(any("google" in v.lower() for v in vals))

    def test_resolve_safe_nxdomain(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("this-domain-absolutely-does-not-exist-xyz123.com", "A")
        self.assertEqual(status, "NXDOMAIN")
        self.assertEqual(vals, [])

    def test_resolve_safe_ns(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("cloudflare.com", "NS")
        self.assertEqual(status, "ok")
        self.assertGreaterEqual(len(vals), 2)

    def test_resolve_safe_txt_spf(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("google.com", "TXT")
        self.assertEqual(status, "ok")
        spf = [v for v in vals if "v=spf1" in v.lower()]
        self.assertGreater(len(spf), 0, "Google should have an SPF record")


# ── Smoke: Email Suite ────────────────────────────────────────────────────────
@skip_no_network
class TestEmailSuiteSmoke(unittest.TestCase):

    def test_collect_spf_google(self):
        from modules.email_suite import collect_spf
        result = collect_spf("google.com")
        self.assertTrue(result["has_record"])
        self.assertIsNotNone(result["record"])
        self.assertLessEqual(result["lookup_count"], 10)

    def test_collect_dmarc_google(self):
        from modules.email_suite import collect_dmarc
        result = collect_dmarc("google.com")
        self.assertTrue(result["has_record"])
        self.assertIn(result["policy"], ("none", "quarantine", "reject"))

    def test_collect_mx_google(self):
        from modules.email_suite import collect_mx
        result = collect_mx("google.com")
        self.assertTrue(result["has_records"])
        self.assertGreater(len(result["records"]), 0)
        for rec in result["records"]:
            self.assertIn("host", rec)
            self.assertIn("priority", rec)


# ── Smoke: Security ───────────────────────────────────────────────────────────
@skip_no_network
class TestSecuritySmoke(unittest.TestCase):

    def test_resolve_caa(self):
        from modules.dns_core import resolve_safe
        # google.com has CAA records
        vals, ttl, status = resolve_safe("google.com", "CAA")
        # Just verify it doesn't error — may or may not have CAA
        self.assertIn(status, ("ok", "NOANSWER", "NXDOMAIN"))

    def test_zone_transfer_refused(self):
        from modules.security import zone_transfer_test
        result = zone_transfer_test("google.com")
        if result:
            self.assertEqual(result["vulnerable"], [],
                             "google.com should NOT allow zone transfers")


# ── Smoke: WHOIS / RDAP ───────────────────────────────────────────────────────
@skip_no_network
class TestWhoisSmoke(unittest.TestCase):

    def test_rdap_lookup_returns_data(self):
        import requests
        resp = requests.get(
            "https://rdap.org/domain/google.com",
            timeout=10,
            headers={"Accept": "application/rdap+json"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ldhName", data)


# ── Smoke: Subdomain Enum ─────────────────────────────────────────────────────
@skip_no_network
class TestSubdomainEnumSmoke(unittest.TestCase):

    def test_www_resolves_for_google(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("www.google.com", "A")
        self.assertEqual(status, "ok")
        self.assertTrue(len(vals) > 0)

    def test_nonsense_subdomain_nxdomain(self):
        from modules.dns_core import resolve_safe
        vals, ttl, status = resolve_safe("zzznoresolve99.google.com", "A")
        self.assertIn(status, ("NXDOMAIN", "NOANSWER", "NO_NS"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
