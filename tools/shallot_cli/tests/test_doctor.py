"""Tester för shallot doctor — devkey-guard utan hårdvarupåverkan."""

from shallot_cli.commands import doctor_cmd


def test_guard_passes_with_opt_in_present():
    assert doctor_cmd._firmware_devkey_guard() == []


def test_guard_covers_edge_file():
    assert "plc/edge-challenge-response/edge-challenge-response.ino" in (
        doctor_cmd.FIRMWARE_GUARD_FILES
    )


def test_guard_flags_unguarded_devkey(tmp_path, monkeypatch):
    victim = tmp_path / "fw.ino"
    victim.write_text("static const uint8_t MASTER_KEY[16] = {0};\n")
    monkeypatch.setattr(doctor_cmd, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(doctor_cmd, "FIRMWARE_GUARD_FILES", ["fw.ino"])
    assert doctor_cmd._firmware_devkey_guard() == ["fw.ino"]


def test_guard_accepts_opt_in_marker(tmp_path, monkeypatch):
    ok_file = tmp_path / "fw.ino"
    ok_file.write_text(
        "#ifndef EDGE_ALLOW_DEV_KEY\n#error bench only\n#endif\n"
        "static const uint8_t MASTER_KEY[16] = {0};\n"
    )
    monkeypatch.setattr(doctor_cmd, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(doctor_cmd, "FIRMWARE_GUARD_FILES", ["fw.ino"])
    assert doctor_cmd._firmware_devkey_guard() == []
