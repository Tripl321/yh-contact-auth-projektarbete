"""Kommandoregistry (biljett 04) — en ägare för registrering.

Varje post beskriver ett CLI-kommando en gång (namn/hjälp/argument/run
+ TUI-nummer/flöde) och konsumeras av både argparse (cli.py) och TUI
(tui.py). Befintliga kommandon migreras inkrementellt; ännu ej
migrerade ligger kvar på legacy-vägen i cli.py/tui.py.

Flödesfunktioner importerar tui-hjälpare sent (funktionslokalt) för att
bryta importcykeln registry <-> tui.
"""

from __future__ import annotations


class Command:
    """Ett registrerat kommando. tui_number/tui_flow None = ingen TUI-post."""

    def __init__(self, name, help_text, add_arguments, run,
                 tui_number=None, tui_flow=None):
        self.name = name
        self.help_text = help_text
        self.add_arguments = add_arguments
        self.run = run
        self.tui_number = tui_number
        self.tui_flow = tui_flow


COMMANDS: dict[str, Command] = {}


def register(cmd: Command) -> Command:
    COMMANDS[cmd.name] = cmd
    return cmd


def _simulate_args(parser):
    from shallot_cli.sim import SCENARIOS
    sub = parser.add_subparsers(dest="what", required=True)
    auth = sub.add_parser("auth", help="simulera DEN–PAW challenge-response")
    auth.add_argument("--scenario", required=True, choices=list(SCENARIOS),
                      help="felscenario att simulera")


def _simulate_run(args):
    from shallot_cli.commands import simulate_cmd
    return simulate_cmd.run(args.scenario)


def _simulate_flow():
    from shallot_cli import tui
    tui._flow_simulate()


def _doctor_flow():
    from shallot_cli import tui
    from shallot_cli.commands import doctor_cmd
    tui.report(doctor_cmd.run())


def _doctor_run(args):
    from shallot_cli.commands import doctor_cmd
    return doctor_cmd.run()


register(Command(
    name="simulate",
    help_text="deterministisk simulering (TEST-ONLY)",
    add_arguments=_simulate_args,
    run=_simulate_run,
    tui_number="3",
    tui_flow=_simulate_flow,
))

register(Command(
    name="doctor",
    help_text="skrivfri miljökontroll",
    add_arguments=lambda parser: None,
    run=_doctor_run,
    tui_number="6",
    tui_flow=_doctor_flow,
))


def dispatch_tui(number: str) -> bool | None:
    """Kör TUI-post via registry. True = känt nummer (kört), None = legacy."""
    for cmd in COMMANDS.values():
        if cmd.tui_number == number and cmd.tui_flow is not None:
            cmd.tui_flow()
            return True
    return None
