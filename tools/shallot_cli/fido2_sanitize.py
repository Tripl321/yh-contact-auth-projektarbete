"""Sanering för FIDO2-spåret. All output saneras före visning, loggning
och eventuell Ollama-analys.

Maskerar: långa/identifierande credential-ID:n, tokens, nycklar, råa
CBOR/CTAP-payloads (hex/base64url-blobbar), privata IP-adresser
(inkl. Tailscale 100.64/10) och personuppgifter (e-post).
Korta interna ID:n (t.ex. ``admin-01``) och statusord lämnas intakta.
"""

from __future__ import annotations

import re

# (mönster, ersättning) — specifikt före generellt.
REDACTIONS = [
    # Nyckel/token med etikett: api_key=..., "token": "...", password: ...
    (re.compile(r"\b(api[_-]?key|private[_-]?key|secret|password|passwd|pwd|token)\b"
                r"\s*[\"']?\s*[:=]\s*[\"']?[^\s\"',}]+[\"']?", re.IGNORECASE),
     lambda m: "%s=[REDACTED]" % m.group(1)),
    (re.compile(r"\bbearer\s+\S+", re.IGNORECASE), "bearer [REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "-----BEGIN REDACTED PRIVATE KEY-----"),
    # Rå CBOR/CTAP-hex: h'deadbeef' eller långa hex-runs.
    (re.compile(r"\bh'[0-9A-Fa-f]+'"), "h'[REDACTED-HEX]'"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[ :]?){16,}"), "[REDACTED-HEX]"),
    (re.compile(r"\b[0-9A-Fa-f]{32,}\b"), "[REDACTED-HEX]"),
    # Credential-ID och andra base64url-blobbar (≥32 tecken).
    (re.compile(r"\b[A-Za-z0-9_-]{32,}={0,2}\b"), "[REDACTED-CRED]"),
    # Privata adresser inkl. Tailscale CGNAT, loopback, link-local.
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3}"
                r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}"
                r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"), "[REDACTED-IP]"),
    (re.compile(r"\bfe80:[0-9A-Fa-f:]*[0-9A-Fa-f]\b"), "[REDACTED-IP]"),
    (re.compile(r"(?<![0-9A-Fa-f:])::1(?![0-9A-Fa-f:])"), "[REDACTED-IP]"),
    # Personuppgifter: e-postadresser.
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "[REDACTED-EMAIL]"),
]


def sanitize(text: str) -> str:
    """Maskera hemligheter och personuppgifter i fri text."""
    out = text or ""
    for pattern, repl in REDACTIONS:
        out = pattern.sub(repl, out)
    return out


def short_credential(credential_id: str) -> str:
    """Visningsform för credential-ID: trunkerat om långt/identifierande."""
    cid = credential_id or ""
    if len(cid) <= 16:
        return cid
    return "cred:%s…%s" % (cid[:8], cid[-4:])
