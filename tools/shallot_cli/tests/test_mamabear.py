"""Tester för MamaBear-fjärrläge. All SSH mockas — inga nätverksanrop."""

import json
import subprocess

import pytest
from shallot_cli import cli, mamabear


def _fake_runner(mapping):
    """mapping: fjärrkommando -> (exit, stdout, stderr) | 'timeout' | 'connfail'."""
    calls = []

    def fake(alias, remote_cmd, timeout_s=30):
        calls.append((alias, remote_cmd, timeout_s))
        spec = mapping.get(remote_cmd, (0, "ok\n", ""))
        if spec == "timeout":
            return {"exit_code": None, "timed_out": True, "stdout": "", "stderr": ""}
        if spec == "connfail":
            return {
                "exit_code": 255,
                "timed_out": False,
                "stdout": "",
                "stderr": "ssh: connect to host x port 22: Connection refused",
            }
        code, out, err = spec
        return {"exit_code": code, "timed_out": False, "stdout": out, "stderr": err}

    return fake, calls


STATUS_OK = {
    "uname -a": (0, "Linux mamabear 6.1.0-rpi8 #1 SMP PREEMPT x86_64 GNU/Linux\n", ""),
    "uptime": (
        0,
        "10:00:00 up 3 days, 2:14, 1 user, load average: 0.05, 0.03, 0.01\n",
        "",
    ),
    "free -m": (0, "MemTotal: 4024548 kB\nMemFree: 3011220 kB\n", ""),
    "df -h /": (
        0,
        "Filesystem Size Used Avail Use% Mounted on\n/dev/root 29G 4.1G 24G 15% /\n",
        "",
    ),
}

TEST_OK = {
    "echo MAMABEAR_SELFTEST_OK": (0, "MAMABEAR_SELFTEST_OK\n", ""),
    "printf 'a\\nb\\n' | wc -l": (0, "2\n", ""),
    "date -u +%Y-%m-%dT%H:%M:%SZ": (0, "2026-09-14T10:00:00Z\n", ""),
}


def test_alias_validation():
    assert mamabear.validate_alias("mamabear") == "mamabear"
    assert mamabear.validate_alias("  mb-01.lan  ") == "mb-01.lan"
    for bad in [
        "100.64.1.5",
        "192.168.1.10",
        "user@mamabear",
        "-oProxyJump=x",
        "a/b",
        "",
        "alias med mellanslag",
        "x" * 65,
        ".",
        "..",
    ]:
        with pytest.raises(ValueError):
            mamabear.validate_alias(bad)


def test_run_remote_rejects_outside_allowlist():
    with pytest.raises(RuntimeError, match="allowlist"):
        mamabear.run_remote("mamabear", "rm -rf /")
    with pytest.raises((ValueError, RuntimeError)):
        mamabear.run_remote("-oProxyJump=x", "uname -a")


def test_ssh_argv_uses_system_config_and_batchmode(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs

        class P:
            returncode = 0
            stdout = "ok\n"
            stderr = ""

        return P()

    monkeypatch.setattr(mamabear.subprocess, "run", fake_run)
    out = mamabear.run_remote("mamabear", "uname -a")
    assert out == {"exit_code": 0, "timed_out": False, "stdout": "ok\n", "stderr": ""}
    assert seen["argv"][:5] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    assert seen["argv"][5:] == ["mamabear", "uname -a"]
    assert seen["kwargs"]["shell"] is False
    assert "-i" not in seen["argv"] and "PasswordAuthentication" not in str(
        seen["argv"]
    )


def test_ssh_missing_binary_fails_closed(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(mamabear.subprocess, "run", boom)
    with pytest.raises(RuntimeError, match="ssh-binären"):
        mamabear.run_remote("mamabear", "uname -a")


def test_ssh_timeout_flagged(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=30)

    monkeypatch.setattr(mamabear.subprocess, "run", boom)
    assert mamabear.run_remote("mamabear", "uname -a")["timed_out"] is True


def test_sanitize_masks_secrets():
    dirty = (
        "key=placeholder_sample api_key: placeholder_sample "
        "bearer TOKEN123 fingerprint=deadbeef token 0123456789abcdef0123456789abcdef "
        "aa:bb:cc:dd:ee:ff 08:00:2b:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:00:11 "
        "ip 100.64.1.5 gw 192.168.1.1 dns 10.0.0.53 lo 127.0.0.1 link fe80::1 end ::1. "
        "password=hunter2 -----BEGIN OPENSSH PRIVATE KEY-----"
    )
    from shallot_cli import fido2_sanitize

    clean = fido2_sanitize.sanitize(dirty)
    for secret in [
        "100.64.1.5",
        "192.168.1.1",
        "10.0.0.53",
        "127.0.0.1",
        "aa:bb:cc:dd:ee:ff",
        "OPENSSH",
    ]:
        assert secret not in clean, secret
    assert "[REDACTED" in clean


def test_sanitize_preserves_benign_status():
    benign = (
        "Linux mamabear 6.1.0-rpi8 #1 SMP PREEMPT x86_64 GNU/Linux\n"
        "10:00:00 up 3 days, 2:14, 1 user, load average: 0.05, 0.03, 0.01\n"
        "MemTotal: 4024548 kB\n/dev/root 29G 4.1G 24G 15% /"
    )
    from shallot_cli import fido2_sanitize

    assert fido2_sanitize.sanitize(benign) == benign


def test_allowlist_is_read_only():
    banned = (
        "sudo",
        "rm ",
        "mv ",
        "dd ",
        "flash",
        "reboot",
        "shutdown",
        "poweroff",
        "passwd",
        "ssh ",
        "curl",
        "wget",
        ">",
        "keygen",
        "provision",
        "upload",
    )
    for entry in mamabear.STATUS_COMMANDS + mamabear.TEST_COMMANDS:
        lowered = entry["cmd"].lower()
        assert not any(b in lowered for b in banned), entry


def test_only_allowlist_commands_reach_ssh(monkeypatch):
    fake, calls = _fake_runner({**STATUS_OK, **TEST_OK})
    monkeypatch.setattr(mamabear, "run_remote", fake)
    mamabear.run_suite("mamabear", mamabear.STATUS_COMMANDS)
    mamabear.run_suite("mamabear", mamabear.TEST_COMMANDS)
    allowed = {e["cmd"] for e in mamabear.STATUS_COMMANDS + mamabear.TEST_COMMANDS}
    assert calls, "ingen SSH-anrop skedde"
    assert {c[1] for c in calls} <= allowed
    assert all(c[0] == "mamabear" for c in calls)


def test_status_success_saves_json_and_summary(capsys, monkeypatch, tmp_path):
    fake, _ = _fake_runner(STATUS_OK)
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "mamabear" in out and "PASS" in out
    files = list(tmp_path.glob("mamabear-status-*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["teststatus"] == "pass" and data["exit_code"] == 0
    assert data["host_alias"] == "mamabear" and data["timestamp_utc"]
    assert data["passed"] == 4 and data["failed"] == 0
    assert "scope_note" in data and "DEN–PAW" in data["scope_note"]
    assert "transpor" in out.lower() or "anslutning" in out


def test_test_success_with_output_flag(capsys, monkeypatch, tmp_path):
    fake, _ = _fake_runner(TEST_OK)
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "custom.json"
    assert (
        cli.main(
            ["mamabear", "test", "--host", "mamabear", "--yes", "--output", str(target)]
        )
        == 0
    )
    data = json.loads(target.read_text())
    assert data["teststatus"] == "pass" and data["passed"] == 3
    assert "custom.json" in capsys.readouterr().out


def test_test_wrong_marker_fails_closed(capsys, monkeypatch, tmp_path):
    bad = dict(TEST_OK, **{"echo MAMABEAR_SELFTEST_OK": (0, "TAMPERED\n", "")})
    fake, _ = _fake_runner(bad)
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "test", "--host", "mamabear", "--yes"]) == 1
    files = list(tmp_path.glob("mamabear-test-*.json"))
    assert len(files) == 1  # misslyckat självtest journalförs ändå lokalt
    data = json.loads(files[0].read_text())
    assert data["teststatus"] == "fail" and data["exit_code"] == 1
    assert "FAIL" in capsys.readouterr().out


def test_connection_failure_fails_closed(capsys, monkeypatch, tmp_path):
    fake, calls = _fake_runner({"uname -a": "connfail"})
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear", "--yes"]) == 1
    assert len(calls) == 1  # avbryt direkt, fortsätt inte pika noden
    out = capsys.readouterr().out
    assert "FEL" in out
    files = list(tmp_path.glob("mamabear-status-*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["teststatus"] == "fail" and data["aborted"] is True


def test_timeout_fails_closed(capsys, monkeypatch, tmp_path):
    fake, _ = _fake_runner({"uname -a": (0, "Linux x\n", ""), "uptime": "timeout"})
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear", "--yes"]) == 1
    files = list(tmp_path.glob("mamabear-status-*.json"))
    data = json.loads(files[0].read_text())
    assert (
        data["teststatus"] == "fail" and len(data["commands"]) == 1
    )  # partiellt sparas


def test_secrets_masked_in_saved_file(monkeypatch, tmp_path):
    leak = (
        "Linux x key=00112233445566778899aabbccddeeff\n"
        "token=supersecretvalue12345678901234567890 ip 100.64.9.9\n"
    )
    fake, _ = _fake_runner(dict(STATUS_OK, **{"uname -a": (0, leak, "")}))
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear", "--yes"]) == 0
    blob = next(tmp_path.glob("mamabear-status-*.json")).read_text()
    for secret in ["00112233", "supersecretvalue", "100.64.9.9"]:
        assert secret not in blob
    assert "[REDACTED" in blob


def test_declined_confirmation_runs_no_ssh(capsys, monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(
        mamabear,
        "run_remote",
        lambda *a, **k: called.append(True)
        or (_ for _ in ()).throw(AssertionError("SSH får inte anropas")),
    )
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear"]) == 2
    assert called == [] and list(tmp_path.glob("*.json")) == []
    assert "Avbrutet" in capsys.readouterr().err


def test_injected_confirm_gates_ssh_without_terminal(capsys, monkeypatch, tmp_path):
    from shallot_cli.commands import mamabear_cmd

    called = []
    monkeypatch.setattr(
        mamabear,
        "run_remote",
        lambda *a, **k: called.append(True)
        or (_ for _ in ()).throw(AssertionError("SSH får inte anropas")),
    )
    monkeypatch.chdir(tmp_path)
    assert mamabear_cmd.run_status("mamabear", confirm=lambda q: False) == 2
    assert called == [] and list(tmp_path.glob("*.json")) == []


def test_confirmed_interactively(capsys, monkeypatch, tmp_path):
    fake, _ = _fake_runner(STATUS_OK)
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.setattr("builtins.input", lambda *a: "j")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear"]) == 0


def test_invalid_host_runs_no_ssh(capsys, monkeypatch):
    called = []
    monkeypatch.setattr(mamabear, "run_remote", lambda *a, **k: called.append(True))
    assert cli.main(["mamabear", "status", "--host", "100.64.1.5", "--yes"]) == 2
    assert cli.main(["mamabear", "test", "--host", "user@mb", "--yes"]) == 2
    assert called == []


def test_missing_output_dir_fails_closed(capsys, monkeypatch, tmp_path):
    fake, _ = _fake_runner(TEST_OK)
    monkeypatch.setattr(mamabear, "run_remote", fake)
    monkeypatch.chdir(tmp_path)
    rc = cli.main(
        [
            "mamabear",
            "test",
            "--host",
            "mamabear",
            "--yes",
            "--output",
            str(tmp_path / "saknas" / "r.json"),
        ]
    )
    assert rc == 1
    assert "målkatalog" in capsys.readouterr().err


def test_tui_mamabear_delegates(monkeypatch):
    import builtins

    from shallot_cli import tui

    calls = []
    monkeypatch.setattr(
        tui.mamabear_cmd,
        "run_status",
        lambda *a, **k: calls.append(("status", a, k)) or 0,
    )
    monkeypatch.setattr(
        tui.mamabear_cmd, "run_test", lambda *a, **k: calls.append(("test", a, k)) or 0
    )
    answers = iter(["10", "1", "mamabear", "10", "2", "mamabear", "", "0"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert tui.run() == 0
    assert calls == [
        ("status", ("mamabear",), {"confirm": tui.confirm}),
        ("test", ("mamabear",), {"confirm": tui.confirm, "output": None}),
    ]


def test_tailnet_policy_deny_is_transport_error():
    denied = {
        "exit_code": 255,
        "timed_out": False,
        "stdout": "",
        "stderr": 'tailscale: tailnet policy does not permit you to SSH as user "johannes"',
    }
    assert mamabear.is_transport_error(denied) is True
    assert (
        mamabear.is_transport_error(
            {"exit_code": 1, "timed_out": False, "stdout": "", "stderr": "fail"}
        )
        is False
    )


def test_policy_deny_aborts_suite_without_command_results(
    capsys, monkeypatch, tmp_path
):
    def denied(alias, remote_cmd, timeout_s=30):
        return {
            "exit_code": 255,
            "timed_out": False,
            "stdout": "",
            "stderr": "tailscale: tailnet policy does not permit you to SSH",
        }

    monkeypatch.setattr(mamabear, "run_remote", denied)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["mamabear", "status", "--host", "mamabear", "--yes"]) == 1
    out = capsys.readouterr().out
    assert "FEL" in out and "exit=" not in out  # abort: inga kommandorader
