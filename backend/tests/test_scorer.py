"""Tests for the scoring engine. Run from backend/:  python3 -m unittest -v

Uses only the synthetic emails in tests/samples (no personal data).
"""

import unittest
from pathlib import Path

from scorer.domains import org_domain
from scorer.engine import score_email
from scorer.parser import MAX_MESSAGE_BYTES, MessageTooLarge, parse_email

SAMPLES = Path(__file__).parent / "samples"


def score(name):
    return score_email((SAMPLES / name).read_bytes())


def ids(result):
    return {s["id"] for s in result["signals"]}


class VerdictTests(unittest.TestCase):
    """End-to-end: each sample gets the verdict a careful human would give."""

    def test_marketing_newsletter_is_safe(self):
        result = score("legit_newsletter.eml")
        self.assertEqual(result["verdict"], "safe")
        # noisy-but-normal things are reported, yet only as weak signals
        self.assertTrue({"D1", "D3", "D6"} <= ids(result))
        self.assertTrue(all(s["strength"] == "weak" for s in result["signals"]))

    def test_verified_receipt_with_pdf_is_safe(self):
        result = score("legit_receipt.eml")
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["score"], 0)

    def test_lookalike_phishing_is_malicious(self):
        result = score("phishing_lookalike.eml")
        self.assertEqual(result["verdict"], "malicious")
        self.assertTrue({"A1", "A3", "B1", "D2", "D5"} <= ids(result))

    def test_public_hosting_phishing_is_malicious(self):
        result = score("phishing_public_hosting.eml")
        self.assertEqual(result["verdict"], "malicious")
        self.assertTrue({"A1", "A4", "B2"} <= ids(result))

    def test_script_from_friend_is_suspicious_not_malicious(self):
        # Verified sender, no deception -> the deception rule must not fire.
        result = score("friend_zip_with_script.eml")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertFalse(result["deception_and_action"])
        self.assertIn("C1", ids(result))

    def test_password_protected_zip_is_flagged(self):
        # Even from a verified sender: locked archives are a classic way to smuggle malware.
        result = score("encrypted_zip_invoice.eml")
        self.assertIn("C3", ids(result))
        self.assertEqual(result["verdict"], "suspicious")


class SecurityTests(unittest.TestCase):

    def test_forged_authentication_header_is_ignored(self):
        # The attacker's own "dmarc=pass" header sits below Gmail's real "dmarc=fail".
        email = parse_email((SAMPLES / "forged_auth_header.eml").read_bytes())
        self.assertIn("dmarc=fail", email.auth_results)
        self.assertNotIn("dmarc=pass", email.auth_results)
        self.assertIn("A1", ids(score("forged_auth_header.eml")))

    def test_oversized_message_is_rejected(self):
        with self.assertRaises(MessageTooLarge):
            parse_email(b"x" * (MAX_MESSAGE_BYTES + 1))

    def test_garbage_input_does_not_crash(self):
        for raw in (b"", b"\x00\xff" * 1000, b"From: <<<>>>\n\n<a href='http://[::1'>x</a>"):
            result = score_email(raw)
            self.assertIn(result["verdict"], ("safe", "suspicious", "malicious"))

    def test_zip_is_listed_not_extracted(self):
        email = parse_email((SAMPLES / "friend_zip_with_script.eml").read_bytes())
        self.assertEqual(email.attachments[0].archive_members, ["homework.py"])


class ScoringRuleTests(unittest.TestCase):

    def test_weak_signal_cap_is_below_malicious_threshold(self):
        from scorer.engine import WEAK_SIGNALS_CAP, MALICIOUS_FROM
        self.assertLess(WEAK_SIGNALS_CAP, MALICIOUS_FROM)

    def test_score_is_bounded(self):
        for path in SAMPLES.glob("*.eml"):
            result = score_email(path.read_bytes())
            self.assertGreaterEqual(result["score"], 0)
            self.assertLessEqual(result["score"], 100)


class DomainTests(unittest.TestCase):

    def test_org_domain(self):
        self.assertEqual(org_domain("mail.uniqlo.co.th"), "uniqlo.co.th")
        self.assertEqual(org_domain("a.b.example.com"), "example.com")
        self.assertEqual(org_domain("sb030.upperivy.web.id"), "upperivy.web.id")
        self.assertEqual(org_domain("EXAMPLE.COM."), "example.com")


if __name__ == "__main__":
    unittest.main()
