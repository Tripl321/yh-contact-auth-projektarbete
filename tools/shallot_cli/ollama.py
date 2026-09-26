"""Minimal Ollama-klient (PRO-100) — endast loopback, stdlib only.

Säkerhetsregler:
- Värden måste vara loopback (localhost/127.0.0.1/::1); allt annat
  avvisas INNAN någon anslutning öppnas — inga data lämnar maskinen.
- Inga API-nycklar, ingen telemetri; endast de två läs/generera-anropen.
- Korta timeouter; alla transportfel blir OllamaError med klartext.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MODEL = "llama3.2"
TAGS_TIMEOUT_S = 5
GENERATE_TIMEOUT_S = 90

_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


class OllamaError(Exception):
    """Tydligt fel: hit nås inte, modellen saknas eller svaret ogiltigt."""


def resolve_base(host: str | None = None) -> str:
    """Normalisera Ollama-bas-URL. Tillåter endast loopback-adresser."""
    raw = (host or os.environ.get("OLLAMA_HOST") or "http://localhost:11434").strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError as e:
        raise OllamaError("ogiltig Ollama-adress %r (%s)" % (raw, e)) from None
    if parts.scheme not in ("http", "https"):
        raise OllamaError("ogiltig Ollama-adress %r (kräver http/https)" % raw)
    if (parts.hostname or "").lower().strip("[]") not in _LOOPBACK_HOSTS:
        raise OllamaError(
            "vägrar icke-lokal Ollama-värd %r — endast localhost tillåts "
            "(ingen data får lämna maskinen)" % raw
        )
    if parts.username or parts.password:
        raise OllamaError("autentiseringsinfo i Ollama-adress stöds inte: %r" % raw)
    return "%s://%s" % (parts.scheme, parts.netloc)


def _read(url: str, data: bytes | None, timeout: int) -> dict:
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        raise OllamaError(
            "Ollama nås inte på %s (%s) — starta med `ollama serve` "
            "och försök igen" % (url, reason)
        ) from None
    except (ValueError, KeyError) as e:
        raise OllamaError("ogiltigt svar från Ollama (%s)" % e) from None


def list_models(base: str) -> list[str]:
    """Modeller via /api/tags. Kastar OllamaError vid fel."""
    payload = _read(base + "/api/tags", None, TAGS_TIMEOUT_S)
    try:
        return [m["name"] for m in payload.get("models", [])]
    except (AttributeError, TypeError, KeyError) as e:
        raise OllamaError("ogiltigt modellsvar från Ollama (%s)" % e) from None


def model_available(base: str, model: str) -> bool:
    """True om modellen finns lokalt (namn eller namn:tagg-prefixmatch)."""
    want = model.split(":")[0]
    return any(m == model or m.split(":")[0] == want for m in list_models(base))


def generate(base: str, model: str, prompt: str) -> str:
    """Generera ett svar (stream=false). Kastar OllamaError vid fel."""
    body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(
        "utf-8"
    )
    payload = _read(base + "/api/generate", body, GENERATE_TIMEOUT_S)
    text = payload.get("response", "")
    if not isinstance(text, str) or not text.strip():
        raise OllamaError("tomt svar från modellen %r" % model)
    return text.strip()
