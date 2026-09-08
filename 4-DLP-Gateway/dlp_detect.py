#!/usr/bin/env python3
"""PII detection helpers for the DLP observability report.

Pure, dependency-free (stdlib ``re`` only) so it is unit-testable in isolation.
This is *detection* used for auditing the gateway logs, not the masking itself
(which lives in the APISIX gateway config).

Design notes:
- Credit-card matching is bounded ({12,18} not ``*?``) to avoid catastrophic
  backtracking (ReDoS) on long numeric strings, and every candidate is
  Luhn-validated to cut false positives (phone numbers, order ids, timestamps).
- IBAN and API-key detection were previously missing entirely even though the
  README advertised masking them.
"""
from __future__ import annotations

import re

# Detection-only patterns (not RFC-perfect; tuned to reduce false positives).
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,24}")

# Bounded quantifier + single optional separator => linear time (ReDoS-safe).
_CC_CANDIDATE_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

# IBAN: 2 letters + 2 check digits + up to 30 alphanumerics.
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

# Known API-key shapes (prefix-anchored to avoid matching arbitrary tokens).
API_KEY_RE = re.compile(
    r"\b("
    r"gsk_[A-Za-z0-9]{20,}"        # Groq
    r"|sk-[A-Za-z0-9]{20,}"        # OpenAI-style
    r"|AKIA[0-9A-Z]{16}"           # AWS access key id
    r"|ghp_[A-Za-z0-9]{36}"        # GitHub PAT
    r")\b"
)


def luhn_valid(number: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def find_credit_cards(text: str) -> list[str]:
    """Return Luhn-valid credit-card-like numbers found in ``text``."""
    out = []
    for m in _CC_CANDIDATE_RE.finditer(text):
        candidate = m.group(0)
        if luhn_valid(candidate):
            out.append(candidate)
    return out


def find_pii(text: str) -> dict[str, list[str]]:
    """Detect PII in ``text``.

    Returns a dict keyed by class ('emails', 'credit_cards', 'ibans',
    'api_keys') mapping to the list of raw matches for each class.
    """
    if not text:
        return {"emails": [], "credit_cards": [], "ibans": [], "api_keys": []}
    return {
        "emails": EMAIL_RE.findall(text),
        "credit_cards": find_credit_cards(text),
        "ibans": IBAN_RE.findall(text),
        "api_keys": [m if isinstance(m, str) else m[0] for m in API_KEY_RE.findall(text)],
    }


def redact(value: str) -> str:
    """Fully redact a PII value for safe display (no plaintext prefix)."""
    return f"[REDACTED:{len(value)} chars]"
