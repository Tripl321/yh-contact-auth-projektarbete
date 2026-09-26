"""Tester för shallot doctor — devkey-guard utan hårdvarupåverkan.

Guardet godkänner edge-filen endast vid ett VERKLIGT fail-closed
preprocessor-guard (utan flaggan stoppas bygget med #error). En
förekomst i kommentar/sträng, en egendefinierad flagga eller ett
ofullständigt guard flaggas — se de negativa testerna nedan.
"""

import pytest
from shallot_cli.commands import doctor_cmd

KEY_LINE = "static const uint8_t MASTER_KEY[16] = {0};\n"
GOOD_GUARD = "#ifndef EDGE_ALLOW_DEV_KEY\n#error bench only\n#endif\n"


def _guard_result(tmp_path, monkeypatch, content):
    victim = tmp_path / "fw.ino"
    victim.write_text(content)
    monkeypatch.setattr(doctor_cmd, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(doctor_cmd, "FIRMWARE_GUARD_FILES", ["fw.ino"])
    return doctor_cmd._firmware_devkey_guard()


def test_guard_passes_with_opt_in_present():
    assert doctor_cmd._firmware_devkey_guard() == []


def test_guard_covers_edge_file():
    assert "plc/edge-challenge-response/edge-challenge-response.ino" in (
        doctor_cmd.FIRMWARE_GUARD_FILES
    )


def test_guard_flags_unguarded_devkey(tmp_path, monkeypatch):
    assert _guard_result(tmp_path, monkeypatch, KEY_LINE) == ["fw.ino"]


def test_guard_accepts_real_fail_closed_guard(tmp_path, monkeypatch):
    assert _guard_result(tmp_path, monkeypatch, GOOD_GUARD + KEY_LINE) == []


def test_guard_accepts_if_not_defined_form(tmp_path, monkeypatch):
    content = "#if !defined(EDGE_ALLOW_DEV_KEY)\n#error bench only\n#endif\n" + KEY_LINE
    assert _guard_result(tmp_path, monkeypatch, content) == []


@pytest.mark.parametrize(
    "fake",
    [
        "// se EDGE_ALLOW_DEV_KEY för bänkbyggen\n",  # radkommentar
        "/* #ifndef EDGE_ALLOW_DEV_KEY\n#error x\n#endif */\n",  # blockkommentar
        'const char* note = "#ifndef EDGE_ALLOW_DEV_KEY";\n',  # strängliteral
        "// #error utanför guard räddar inget\n#error alltid stopp\n",  # ovillkorligt stopp = trasig fil
    ],
    ids=["line-comment", "block-comment", "string-literal", "unconditional-error"],
)
def test_guard_flags_fake_markers(tmp_path, monkeypatch, fake):
    assert _guard_result(tmp_path, monkeypatch, fake + KEY_LINE) == ["fw.ino"]


def test_guard_flags_self_defined_flag(tmp_path, monkeypatch):
    """En egen #define av flaggan gör guardet till teater — flaggas."""
    content = "#define EDGE_ALLOW_DEV_KEY 1\n" + GOOD_GUARD + KEY_LINE
    assert _guard_result(tmp_path, monkeypatch, content) == ["fw.ino"]


def test_guard_flags_ifdef_without_error(tmp_path, monkeypatch):
    """#ifdef utan #error stoppar inte bygget utan flaggan — flaggas."""
    content = "#ifdef EDGE_ALLOW_DEV_KEY\n" + KEY_LINE + "#endif\n"
    assert _guard_result(tmp_path, monkeypatch, content) == ["fw.ino"]


def test_guard_flags_backwards_guard(tmp_path, monkeypatch):
    """#error i #else-grenen stoppar bänkbygget, inte defaultbygget."""
    content = (
        "#ifndef EDGE_ALLOW_DEV_KEY\n#else\n#error wrong branch\n#endif\n" + KEY_LINE
    )
    assert _guard_result(tmp_path, monkeypatch, content) == ["fw.ino"]


def test_guard_flags_nested_hidden_error(tmp_path, monkeypatch):
    """#error gömd i ett inre #if kan vara falskt utan flaggan."""
    content = (
        "#ifndef EDGE_ALLOW_DEV_KEY\n"
        "#if SOME_OTHER_FLAG\n#error maybe\n#endif\n"
        "#endif\n" + KEY_LINE
    )
    assert _guard_result(tmp_path, monkeypatch, content) == ["fw.ino"]


def test_guard_flags_nested_guard(tmp_path, monkeypatch):
    """Guardet måste stå på toppnivå — nästlat i ett annat villkor
    utvärderas det kanske aldrig utan flaggan."""
    content = (
        "#if SOME_PLATFORM\n"
        "#ifndef EDGE_ALLOW_DEV_KEY\n#error bench only\n#endif\n"
        "#endif\n" + KEY_LINE
    )
    assert _guard_result(tmp_path, monkeypatch, content) == ["fw.ino"]
