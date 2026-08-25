"""Automated tests for redact.core.redact_text().

Run with: python3 -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redact.core import redact_text, is_ipv6_like  # noqa: E402


class TestIPv4(unittest.TestCase):
    def test_basic_ipv4(self):
        self.assertEqual(
            redact_text("server at 192.168.100.14 is up"),
            "server at [REDACTED-IP] is up",
        )

    def test_ipv4_with_cidr(self):
        self.assertEqual(
            redact_text("subnet 10.0.0.0/24"),
            "subnet [REDACTED-IP]",
        )

    def test_public_ipv4(self):
        self.assertEqual(
            redact_text("client ip 203.0.113.42 connected"),
            "client ip [REDACTED-IP] connected",
        )


class TestIPv6(unittest.TestCase):
    def test_full_ipv6(self):
        self.assertEqual(
            redact_text("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "addr [REDACTED-IP]",
        )

    def test_compressed_ipv6(self):
        self.assertEqual(
            redact_text("addr fe80::1a2b:3c4d:5e6f"),
            "addr [REDACTED-IP]",
        )

    def test_loopback_ipv6(self):
        self.assertEqual(
            redact_text("bind to ::1 please"),
            "bind to [REDACTED-IP] please",
        )

    def test_timestamp_not_redacted(self):
        # Timestamps look superficially like IPv6 (colon-separated groups)
        # but must NOT be redacted.
        text = "log line at 14:32:10 and another at 09:15:00"
        self.assertEqual(redact_text(text), text)

    def test_is_ipv6_like_rejects_timestamp(self):
        self.assertFalse(is_ipv6_like("10:00:01"))

    def test_is_ipv6_like_accepts_double_colon(self):
        self.assertTrue(is_ipv6_like("::1"))

    def test_is_ipv6_like_accepts_hex_letters(self):
        self.assertTrue(is_ipv6_like("fe80::1"))


class TestHostname(unittest.TestCase):
    def test_internal_hostname(self):
        self.assertEqual(
            redact_text("connect to db-primary.lear-corp.local now"),
            "connect to [REDACTED-HOSTNAME] now",
        )

    def test_public_domain(self):
        self.assertEqual(
            redact_text("API at api.example.com responded"),
            "API at [REDACTED-HOSTNAME] responded",
        )

    def test_extra_domain_flag(self):
        self.assertEqual(
            redact_text(
                "host db.custom-tld.example connected",
                extra_domains=["custom-tld.example"],
            ),
            "host [REDACTED-HOSTNAME] connected",
        )

    def test_bare_word_not_redacted(self):
        text = "webserver01 is running"
        self.assertEqual(redact_text(text), text)


class TestEmail(unittest.TestCase):
    def test_basic_email(self):
        self.assertEqual(
            redact_text("contact marcelo@example.com for help"),
            "contact [REDACTED-EMAIL] for help",
        )

    def test_email_with_client_domain_flag(self):
        # Email must fully redact even when its domain also matches --domain
        self.assertEqual(
            redact_text(
                "escalate to support@lear-corp.example please",
                extra_domains=["lear-corp.example"],
            ),
            "escalate to [REDACTED-EMAIL] please",
        )


class TestMac(unittest.TestCase):
    def test_mac_address(self):
        self.assertEqual(
            redact_text("mac addr: 00:1A:2B:3C:4D:5E"),
            "mac addr: [REDACTED-MAC]",
        )


class TestCredentials(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertEqual(
            redact_text("key: AKIAABCDEFGHIJKLMNOP"),
            "key: [REDACTED-CREDENTIAL]",
        )

    def test_password_assignment(self):
        self.assertEqual(
            redact_text("password=Sup3rS3cr3t!2026"),
            "password=[REDACTED-CREDENTIAL]",
        )

    def test_quoted_api_key(self):
        self.assertEqual(
            redact_text('api_key: "AKIAABCDEFGHIJKLMNOP"'),
            'api_key: "[REDACTED-CREDENTIAL]"',
        )

    def test_github_token(self):
        self.assertEqual(
            redact_text("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
            "token: [REDACTED-CREDENTIAL]",
        )

    def test_bearer_token(self):
        result = redact_text("Authorization: Bearer abcdef0123456789ABCDEF")
        self.assertIn("Bearer [REDACTED-CREDENTIAL]", result)

    def test_pem_private_key_block(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA1234567890\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertEqual(redact_text(pem), "[REDACTED-CREDENTIAL]")


class TestCombined(unittest.TestCase):
    def test_realistic_log_line(self):
        line = (
            "2026-08-24 10:00:01 server01.internal sshd: Accepted publickey "
            "for msmarcal from 192.168.100.14 port 52344"
        )
        result = redact_text(line)
        self.assertIn("10:00:01", result)  # timestamp preserved
        self.assertIn("[REDACTED-HOSTNAME]", result)
        self.assertIn("[REDACTED-IP]", result)
        self.assertNotIn("192.168.100.14", result)
        self.assertNotIn("server01.internal", result)


if __name__ == '__main__':
    unittest.main()
