"""Ticket 04: registry äger registrering för argparse + TUI."""

from shallot_cli import cli, registry, tui


def test_registry_holds_simulate_and_doctor():
    assert set(registry.COMMANDS) >= {"simulate", "doctor"}
    assert registry.COMMANDS["simulate"].tui_number == "3"
    assert registry.COMMANDS["doctor"].tui_number == "6"


def test_argparse_built_from_registry():
    args = cli.build_parser().parse_args(["simulate", "auth", "--scenario", "success"])
    assert args.command == "simulate" and args.scenario == "success"
    args = cli.build_parser().parse_args(["doctor"])
    assert args.command == "doctor"


def test_dispatch_tui_known_and_unknown(monkeypatch, capsys):
    assert registry.dispatch_tui("6") is True  # doctor via registry
    assert registry.dispatch_tui("99") is None  # legacy/okänt: faller igenom
    assert tui.handle_choice("99") is False


def test_simulate_still_delegates(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *a: "1")
    assert cli.main(["simulate", "auth", "--scenario", "success"]) == 0
    assert "SIMULATED" in capsys.readouterr().out.upper()
