"""Tester för shallot CLI-endpoints: exit-koder, roundtrip, vägran att bygga."""

import json

import pytest
from shallot_cli import cli, serial_adapters
from shallot_cli.sim import SCENARIOS


def test_protocol_encode_decode_roundtrip(capsys):
    assert (
        cli.main(
            [
                "protocol",
                "encode",
                "--type",
                "challenge",
                "--payload",
                "0001020304050607",
            ]
        )
        == 0
    )
    frame = capsys.readouterr().out.strip()
    assert frame == "aa08000100010203040506071cf3b72b"
    assert cli.main(["protocol", "decode", "--frame", frame]) == 0
    out = capsys.readouterr().out
    assert "challenge" in out and "OK" in out


def test_protocol_errors(capsys):
    assert cli.main(["protocol", "encode", "--type", "unlock", "--payload", ""]) == 2
    assert (
        cli.main(["protocol", "encode", "--type", "challenge", "--payload", "00"]) == 2
    )
    assert (
        cli.main(["protocol", "encode", "--type", "challenge", "--payload", "zz"]) == 2
    )
    bad = bytearray.fromhex("aa0100ff019d75db7d")
    bad[-1] ^= 0x01
    assert cli.main(["protocol", "decode", "--frame", bytes(bad).hex()]) == 1
    assert cli.main(["protocol", "decode", "--frame", "zz"]) == 2


def test_simulate_all_scenarios(capsys):
    for name in SCENARIOS:
        assert cli.main(["simulate", "auth", "--scenario", name]) == 0
        out = capsys.readouterr().out
        assert "SIMULATED / TEST-ONLY" in out
        assert "nonce" in out and "beslut" in out


def test_build_dry_run_shows_without_running(capsys):
    assert cli.main(["build", "paw", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert (
        "arduino-cli" in out
        and "compile" in out
        and "upload" not in out.split("kommando:")[1].split("\n")[0]
    )
    assert cli.main(["build", "den", "--dry-run"]) == 0
    assert "rpipico2" in capsys.readouterr().out


def test_build_mamabear_reports_no_cli_command(capsys):
    assert cli.main(["build", "mamabear", "--dry-run"]) == 0
    assert "inget verifierat CLI-byggkommando" in capsys.readouterr().out


def test_build_without_dry_run_refused(capsys):
    assert cli.main(["build", "den"]) == 2
    err = capsys.readouterr().err
    assert "--hardware" in err


def test_device_list(capsys):
    assert cli.main(["device", "list"]) == 0
    out = capsys.readouterr().out
    assert "serieport" in out.lower() or "PORT" in out


def test_monitor_reads_without_writing(capsys, monkeypatch):
    lines = [b"[DEN] CHALLENGE sent\n", b"[DEN] AUTHENTICATED (code 0)\n"]

    class FakeSerial:
        def __init__(self):
            self.writes = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def readline(self):
            if not lines:
                raise KeyboardInterrupt
            return lines.pop(0)

        def write(self, data):  # pragma: no cover — får aldrig anropas
            self.writes.append(data)
            raise AssertionError("monitor får aldrig skriva")

    fake = FakeSerial()
    monkeypatch.setattr(serial_adapters, "open_read_only", lambda *a, **k: fake)
    assert cli.main(["monitor", "--device", "den", "--port", "/dev/ttyFAKE"]) == 0
    out = capsys.readouterr().out
    assert "AUTHENTICATED" in out
    assert fake.writes == []


def test_read_until_matches_split_lines_and_times_out(monkeypatch):
    from shallot_cli.commands import monitor_cmd

    chunks = [b"[DEN] AUTHENT", b"ICATED (code 0)\nrest\n"]

    class FakeSerial:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def readline(self):
            if not chunks:
                return b""
            return chunks.pop(0)

    monkeypatch.setattr(
        monitor_cmd.serial_adapters, "open_read_only", lambda *a, **k: FakeSerial()
    )
    hit, line = monitor_cmd.read_until(
        "/dev/ttyX", 115200, ["[DEN] AUTHENTICATED (code 0)"], timeout=5.0
    )
    assert hit == "[DEN] AUTHENTICATED (code 0)"
    assert "AUTHENTICATED" in line
    assert monitor_cmd.read_until("/dev/ttyX", 115200, ["NEVER"], timeout=0.05) == (
        None,
        None,
    )
    assert monitor_cmd.read_until("", 115200, ["x"]) == (None, None)
    assert monitor_cmd.read_until("/dev/ttyX", 0, ["x"]) == (None, None)


def test_monitor_sanitizes_secrets_and_validates_baud(capsys, monkeypatch):
    lines = [b"token supersecretvalue12345678901234567890 ip 169.254.169.254\n"]

    class FakeSerial:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def readline(self):
            if not lines:
                raise KeyboardInterrupt
            return lines.pop(0)

    monkeypatch.setattr(serial_adapters, "open_read_only", lambda *a, **k: FakeSerial())
    assert cli.main(["monitor", "--device", "den", "--port", "/dev/ttyFAKE"]) == 0
    out = capsys.readouterr().out
    assert "supersecretvalue" not in out and "169.254.169.254" not in out
    assert "[REDACTED" in out
    assert (
        cli.main(
            ["monitor", "--device", "den", "--port", "/dev/ttyFAKE", "--baud", "0"]
        )
        == 2
    )


def test_doctor_runs(capsys):
    assert cli.main(["doctor"]) in (0, 1)
    assert "doctor" in capsys.readouterr().out.lower()


def test_test_suite_json_protocol(capsys):
    assert cli.main(["test", "protocol", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["suite"] == "protocol"
    assert data["failed"] == 0 and data["errors"] == 0
    assert data["passed"] > 0 and data["ok"] is True


def test_test_unknown_suite_exits_2():
    with pytest.raises(SystemExit) as e:
        cli.main(["test", "finns-inte"])
    assert e.value.code == 2


def test_stream_pytest_prints_live_and_returns_output(capsys):
    import sys

    from shallot_cli.commands import test_cmd

    out, rc = test_cmd._stream_pytest([sys.executable, "-c", "print('live-rad')"])
    assert rc == 0 and "live-rad" in out
    assert "live-rad" in capsys.readouterr().out  # strömmad, inte buffrad
