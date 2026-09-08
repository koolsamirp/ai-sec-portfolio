"""Offline unit tests for the DLP PII-detection helpers.

Loaded by path because the module lives under a numbered pipeline directory.
No network, no external deps (stdlib ``re`` only).
"""
import importlib.util
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parent.parent / "4-DLP-Gateway" / "dlp_detect.py"
_spec = importlib.util.spec_from_file_location("dlp_detect", _MODULE_PATH)
dlp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dlp)


class TestLuhn:
    def test_valid_visa(self):
        assert dlp.luhn_valid("4111111111111111")  # canonical Visa test number

    def test_valid_mastercard(self):
        assert dlp.luhn_valid("5555555555554444")

    def test_invalid_number(self):
        assert not dlp.luhn_valid("1234567890123456")

    def test_too_short(self):
        assert not dlp.luhn_valid("411111")


class TestCreditCards:
    def test_detects_luhn_valid_with_spaces(self):
        found = dlp.find_credit_cards("card 4111 1111 1111 1111 on file")
        assert any("4111" in c for c in found)

    def test_ignores_random_long_digits(self):
        # 16 digits but not Luhn-valid -> must not be reported.
        assert dlp.find_credit_cards("order id 1234567890123456") == []

    def test_ignores_timestamps(self):
        assert dlp.find_credit_cards("ts=17888839600001788883960") == []


class TestEmail:
    def test_detects_email(self):
        assert "a.user@example.com" in dlp.find_pii("mail a.user@example.com now")["emails"]


class TestIBAN:
    def test_detects_iban(self):
        assert "DE89370400440532013000" in dlp.find_pii("IBAN DE89370400440532013000")["ibans"]


class TestApiKeys:
    def test_detects_groq_and_openai_keys(self):
        keys = dlp.find_pii("k1 gsk_abcdefghijklmnopqrstuvwx k2 sk-abcdefghijklmnopqrstuvwx")["api_keys"]
        assert any(k.startswith("gsk_") for k in keys)
        assert any(k.startswith("sk-") for k in keys)

    def test_detects_aws_key(self):
        assert dlp.find_pii("AKIAIOSFODNN7EXAMPLE")["api_keys"] == ["AKIAIOSFODNN7EXAMPLE"]


class TestRedact:
    def test_redaction_hides_value(self):
        r = dlp.redact("secret@example.com")
        assert "secret" not in r and "REDACTED" in r
