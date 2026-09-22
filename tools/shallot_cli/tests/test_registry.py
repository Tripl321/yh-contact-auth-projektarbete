"""Ticket 04: registry äger registrering för argparse + TUI (alla kommandon)."""

from shallot_cli import cli, registry, tui


def test_registry_holds_all_commands():
    assert set(registry.COMMANDS) == {
        "test", "simulate", "demo", "explain", "protocol", "doctor",
        "build", "device", "monitor", "mamabear", "fido2", "admin",
    }


def test_menu_covers_legacy_numbers_plus_demo_explain():
    numbers = [n for n, _label in registry.menu_entries()]
    assert numbers == list(range(1, 27))


def test_argparse_built_from_registry():
    args = cli.build_parser().parse_args(["simulate", "auth", "--scenario", "success"])
    assert args.command == "simulate" and args.scenario == "success"
    args = cli.build_parser().parse_args(["doctor"])
    assert args.command == "doctor"
    args = cli.build_parser().parse_args(["fido2", "device", "list"])
    assert (args.command, args.what, args.devop) == ("fido2", "device", "list")


def test_dispatch_tui_known_and_unknown(monkeypatch, capsys):
    assert registry.dispatch_tui("6") is True  # doctor via registry
    assert registry.dispatch_tui("99") is False  # okänt: faller igenom
    assert tui.handle_choice("99") is False


def test_all_tui_flows_resolve_to_callables():
    for cmd in registry.COMMANDS.values():
        for number, (_label, flow) in cmd.tui.items():
            fn = getattr(tui, flow, None) if isinstance(flow, str) else flow
            assert callable(fn), (cmd.name, number, flow)


def test_simulate_still_delegates(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *a: "1")
    assert cli.main(["simulate", "auth", "--scenario", "success"]) == 0
    assert "SIMULATED" in capsys.readouterr().out.upper()


def test_demo_and_explain_in_tui_menu(capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: (_ for _ in ()).throw(EOFError))
    tui.run()
    out = capsys.readouterr().out
    assert "20  Simulerad incident" in out
    assert "21  Förklara begrepp" in out
