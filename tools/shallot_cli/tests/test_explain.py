"""Tester för shallot explain + lokal Ollama-klient (PRO-100).

Allt utom ett explicit markerat undantag körs utan nätverk: urlopen
monkeypatchas till att explodera om den rörs. Inga hemligheter får
förekomma i ämnen eller promptar.
"""

import io
import json
import re
import urllib.error

import pytest

from shallot_cli import cli, explain, ollama
from shallot_cli.commands import explain_cmd


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _no_net(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("nätverk anropat i offlinetest")
    monkeypatch.setattr(ollama.urllib.request, "urlopen", boom)


def _fake_tags(monkeypatch, models):
    def fake(req, timeout=None):
        assert req.full_url.endswith("/api/tags")
        return _Resp(json.dumps({"models": [{"name": m} for m in models]}).encode())
    monkeypatch.setattr(ollama.urllib.request, "urlopen", fake)


def _fake_generate(monkeypatch, text, models=("llama3.2:latest",)):
    seen = {}

    def fake(req, timeout=None):
        if req.full_url.endswith("/api/tags"):
            return _Resp(json.dumps({"models": [{"name": m} for m in models]}).encode())
        assert req.full_url.endswith("/api/generate")
        seen["body"] = json.loads(req.data.decode())
        return _Resp(json.dumps({"response": text}).encode())
    monkeypatch.setattr(ollama.urllib.request, "urlopen", fake)
    return seen


def test_local_topics_render_offline(monkeypatch, capsys):
    _no_net(monkeypatch)
    for name in explain.topic_names():
        assert cli.main(["explain", name]) == 0
        out = capsys.readouterr().out
        assert explain.TOPICS[name][0] in out
        assert "ingen extern tjänst" in out.lower()


def test_list_topics(monkeypatch, capsys):
    _no_net(monkeypatch)
    assert cli.main(["explain", "--list"]) == 0
    out = capsys.readouterr().out
    for name in explain.topic_names():
        assert name in out


def test_unknown_topic_exits_2(monkeypatch, capsys):
    _no_net(monkeypatch)
    assert cli.main(["explain", "kärnkraft"]) == 2
    assert "okänt ämne" in capsys.readouterr().err


def test_topics_contain_no_secret_material():
    blob = "\n".join(t + b for t, b in explain.TOPICS.values())
    blob += explain.build_prompt("auth")
    assert not re.search(r"\b[0-9a-fA-F]{8,}\b", blob)
    for word in ("aesKey", "kMac", "kEnc", "denDevKey", "private_key", "MASTER_KEY"):
        assert word not in blob


def test_prompt_uses_only_curated_text():
    prompt = explain.build_prompt("fail-closed")
    title, body = explain.TOPICS["fail-closed"]
    assert title in prompt and body in prompt
    assert "150 ord" in prompt


def test_ai_success_appends_elaboration(monkeypatch, capsys):
    seen = _fake_generate(monkeypatch, "Utvecklad förklaring.")
    assert cli.main(["explain", "auth", "--ai"]) == 0
    out = capsys.readouterr().out
    assert "Utvecklad förklaring." in out
    assert "ej auktoritativ" in out
    assert seen["body"]["model"] == "llama3.2"
    assert "Challenge-response" in seen["body"]["prompt"]


def test_ai_missing_server_clear_error(monkeypatch, capsys):
    def down(*a, **k):
        raise urllib.error.URLError("Connection refused")
    monkeypatch.setattr(ollama.urllib.request, "urlopen", down)
    assert cli.main(["explain", "auth", "--ai"]) == 2
    res = capsys.readouterr()
    out, err = res.out, res.err
    assert "Challenge-response" in out  # lokal text visas ändå
    assert "ollama serve" in err


def test_ai_missing_model_suggests_pull(monkeypatch, capsys):
    _fake_tags(monkeypatch, ["other-model:latest"])
    assert cli.main(["explain", "auth", "--ai", "--model", "saknad-modell"]) == 2
    err = capsys.readouterr().err
    assert "saknas lokalt" in err and "ollama pull saknad-modell" in err


def test_ai_empty_answer_is_error(monkeypatch, capsys):
    _fake_generate(monkeypatch, "   ")
    assert cli.main(["explain", "auth", "--ai"]) == 2
    assert "tomt svar" in capsys.readouterr().err


def test_non_loopback_host_refused_without_request(monkeypatch, capsys):
    _no_net(monkeypatch)
    assert cli.main(["explain", "auth", "--ai", "--host",
                     "http://192.168.1.10:11434"]) == 2
    assert "endast localhost" in capsys.readouterr().err


def test_resolve_base_loopback_forms():
    assert ollama.resolve_base(None).endswith(":11434")
    assert ollama.resolve_base("localhost:11434") == "http://localhost:11434"
    assert ollama.resolve_base("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert ollama.resolve_base("http://[::1]:11434") == "http://[::1]:11434"


def test_resolve_base_rejects_remote(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    for bad in ("http://example.com", "http://10.0.0.5:11434",
                "https://ollama.example.com", "ftp://localhost/x",
                "http://user:pass@localhost:11434"):
        with pytest.raises(ollama.OllamaError):
            ollama.resolve_base(bad)


def test_resolve_base_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    assert ollama.resolve_base(None) == "http://127.0.0.1:11434"


def test_model_available_prefix_match(monkeypatch):
    _fake_tags(monkeypatch, ["llama3.2:latest"])
    assert ollama.model_available("http://localhost:11434", "llama3.2") is True
    assert ollama.model_available("http://localhost:11434", "mistral") is False
