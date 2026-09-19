"""Tester för shallot TUI-läge: meny, bekräftelser, avbrott, delegering."""

import builtins

import pytest

from shallot_cli import cli, tui
from shallot_cli.commands import build_cmd, test_cmd
from shallot_cli.sim import SCENARIOS


def _inputs(monkeypatch, values):
    it = iter(values)

    def fake(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr(builtins, "input", fake)


def test_header_shown_and_quit(capsys, monkeypatch):
    _inputs(monkeypatch, ["0"])
    assert tui.run() == 0
    out = capsys.readouterr().out
    assert "██" in out
    assert "Avslutar." in out


def test_invalid_choice_then_quit(capsys, monkeypatch):
    _inputs(monkeypatch, ["x", "0"])
    assert tui.run() == 0
    assert "Ogiltigt val" in capsys.readouterr().out


def test_empty_input_redisplays(capsys, monkeypatch):
    _inputs(monkeypatch, ["", "0"])
    assert tui.run() == 0


def test_eof_quits_cleanly(capsys, monkeypatch):
    def boom(prompt=""):
        raise EOFError

    monkeypatch.setattr(builtins, "input", boom)
    assert tui.run() == 0
    assert "Avslutar" in capsys.readouterr().out


def test_ctrl_c_at_menu_quits(capsys, monkeypatch):
    def boom(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", boom)
    assert tui.run() == 0
    assert "Avslutar." in capsys.readouterr().out


def test_simulate_marks_test_only(capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(tui.simulate_cmd, "run",
                        lambda scenario: calls.append(scenario) or 0)
    _inputs(monkeypatch, ["3", "1", "0"])
    assert tui.run() == 0
    assert calls == [list(SCENARIOS)[0]]
    assert "SIMULATED / TEST-ONLY" in capsys.readouterr().out


def test_simulate_real_output_marked(capsys, monkeypatch):
    _inputs(monkeypatch, ["3", "1", "0"])
    assert tui.run() == 0
    out = capsys.readouterr().out
    assert out.count("SIMULATED / TEST-ONLY") >= 2  # meny + simuleringsbanner


def test_simulate_invalid_scenario_back_to_menu(capsys, monkeypatch):
    called = []
    monkeypatch.setattr(tui.simulate_cmd, "run",
                        lambda scenario: called.append(scenario) or 0)
    _inputs(monkeypatch, ["3", "99", "0"])
    assert tui.run() == 0
    assert called == []
    assert "Ogiltigt val" in capsys.readouterr().out


def test_test_suite_choice_delegates(monkeypatch):
    calls = []
    monkeypatch.setattr(tui.test_cmd, "run_suite",
                        lambda suite, as_json=False: calls.append(suite) or 0)
    _inputs(monkeypatch, ["2", "2", "0"])
    assert tui.run() == 0
    assert calls == [sorted(test_cmd.SUITES)[1]]


def test_monitor_declined_without_confirm(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(tui.monitor_cmd, "run",
                        lambda *a, **k: calls.append((a, k)) or 0)
    monkeypatch.setattr(tui.serial_adapters, "list_ports",
                        lambda: [{"device": "/dev/ttyACM0",
                                  "description": "d", "hwid": "h"}])
    _inputs(monkeypatch, ["9", "1", "", "n", "0"])
    assert tui.run() == 0
    assert calls == []
    assert "Avbrutet" in capsys.readouterr().out


def test_monitor_confirmed_with_explicit_port(monkeypatch):
    calls = []
    monkeypatch.setattr(tui.monitor_cmd, "run",
                        lambda *a, **k: calls.append((a, k)) or 0)
    monkeypatch.setattr(tui.serial_adapters, "list_ports", lambda: [])
    _inputs(monkeypatch, ["9", "1", "/dev/ttyUSB0", "j", "0"])
    assert tui.run() == 0
    assert calls == [(("den", "/dev/ttyUSB0"), {})]


def test_build_is_dry_run_only(monkeypatch):
    calls = []
    monkeypatch.setattr(tui.build_cmd, "run",
                        lambda *a, **k: calls.append((a, k)) or 0)
    _inputs(monkeypatch, ["7", "1", "0"])
    assert tui.run() == 0
    assert calls == [((sorted(build_cmd.TARGETS)[0],), {"dry_run": True})]


def test_encode_decode_doctor_device_delegate(monkeypatch):
    calls = []
    monkeypatch.setattr(tui.protocol_cmd, "run_encode",
                        lambda t, p: calls.append(("enc", t, p)) or 0)
    monkeypatch.setattr(tui.protocol_cmd, "run_decode",
                        lambda f: calls.append(("dec", f)) or 0)
    monkeypatch.setattr("shallot_cli.commands.doctor_cmd.run",
                        lambda: calls.append("doctor") or 0)
    monkeypatch.setattr(tui.device_cmd, "run_list",
                        lambda: calls.append("devices") or 0)
    _inputs(monkeypatch, ["4", "challenge", "0001020304050607",
                          "5", "aa000003a8884866", "6", "8", "0"])
    assert tui.run() == 0
    assert calls == [("enc", "challenge", "0001020304050607"),
                     ("dec", "aa000003a8884866"), "doctor", "devices"]


def test_main_without_args_launches_tui(monkeypatch):
    called = []
    monkeypatch.setattr(tui, "run", lambda: called.append(True) or 0)
    assert cli.main([]) == 0
    assert called == [True]


def test_main_none_argv_launches_tui(monkeypatch):
    called = []
    monkeypatch.setattr(tui, "run", lambda: called.append(True) or 0)
    monkeypatch.setattr("sys.argv", ["shallot"])
    assert cli.main(None) == 0
    assert called == [True]


def test_existing_subcommand_still_works(capsys):
    assert cli.main(["device", "list"]) == 0


def test_fido2_menu_delegates_to_same_command_logic(monkeypatch):
    calls = []
    monkeypatch.setattr(tui.fido2_cmd, "run_register",
                        lambda *a, **k: calls.append(("register", a, k)) or 0)
    monkeypatch.setattr(tui.fido2_cmd, "run_authenticate",
                        lambda *a, **k: calls.append(("authenticate", a, k)) or 0)
    monkeypatch.setattr(tui.fido2_cmd, "run_credential_list",
                        lambda: calls.append("list") or 0)
    monkeypatch.setattr(tui.fido2_cmd, "run_credential_revoke",
                        lambda *a, **k: calls.append(("revoke", a, k)) or 0)
    monkeypatch.setattr(tui.fido2_cmd, "run_simulate",
                        lambda *a, **k: calls.append(("simulate", a, k)) or 0)
    monkeypatch.setattr(tui.fido2_cmd, "run_audit",
                        lambda: calls.append("audit") or 0)
    _inputs(monkeypatch, ["11", "admin-01", "", "j", "j",
                          "12", "admin-01", "", "", "n",
                          "13", "14", "cred-1", "j",
                          "15", "1", "16", "0"])
    assert tui.run() == 0
    assert calls == [("register", ("admin-01",), {"yes": True, "hardware": False,
                                                  "require_uv": True}),
                     ("authenticate", ("admin-01",),
                      {"credential": None, "hardware": False, "require_uv": False}),
                     "list", ("revoke", ("cred-1",), {"yes": True}),
                     ("simulate", ("success",), {}), "audit"]


def test_fido2_register_declined_in_tui(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(tui.fido2_cmd, "run_register",
                        lambda *a, **k: called.append(True) or 0)
    _inputs(monkeypatch, ["11", "admin-01", "", "n", "n", "0"])
    assert tui.run() == 0
    assert called == []
    assert "Avbrutet" in capsys.readouterr().out


def test_fido2_device_list_in_tui(monkeypatch):
    called = []
    monkeypatch.setattr(tui.fido2_cmd, "run_device_list",
                        lambda: called.append(True) or 0)
    _inputs(monkeypatch, ["17", "0"])
    assert tui.run() == 0
    assert called == [True]


def test_fido2_export_in_tui(monkeypatch):
    called = []
    monkeypatch.setattr(tui.fido2_cmd, "run_credential_export",
                        lambda *a, **k: called.append((a, k)) or 0)
    _inputs(monkeypatch, ["18", "cred-9", "ut.json", "0"])
    assert tui.run() == 0
    assert called == [(("cred-9", "ut.json"), {})]


def test_fido2_set_policy_in_tui(monkeypatch):
    called = []
    monkeypatch.setattr(tui.fido2_cmd, "run_credential_set_policy",
                        lambda *a, **k: called.append((a, k)) or 0)
    _inputs(monkeypatch, ["19", "cred-9", "1", "j", "0"])
    assert tui.run() == 0
    assert called == [(("cred-9", "required"), {"yes": True})]
