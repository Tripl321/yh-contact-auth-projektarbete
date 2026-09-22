"""Kommandoregistry — en ägare för registrering (biljett 04).

Varje post beskriver ett CLI-kommando en gång (namn/hjälp/argument/run
+ TUI-poster som nummer -> (menylabel, flöde)) och konsumeras av både
argparse (cli.py) och TUI (tui.py). Flödesfunktioner bor i tui.py (där
testernas delegerings-seams finns); här refereras de vid namn (str) —
eller som callable för triviala direktanrop — och slås upp sent för
att bryta importcykeln registry <-> tui.
"""

from __future__ import annotations

import sys


class Command:
    """Ett registrerat kommando.

    tui: dict[nummer, (menylabel, flöde)] | None. Flöde är antingen
    namnet på en tui.py-funktion (str) eller ett callable.
    """

    def __init__(self, name, help_text, add_arguments, run, tui=None):
        self.name = name
        self.help_text = help_text
        self.add_arguments = add_arguments
        self.run = run
        self.tui = tui or {}


COMMANDS: dict[str, Command] = {}


def register(cmd: Command) -> Command:
    COMMANDS[cmd.name] = cmd
    return cmd


def dispatch_tui(number: str) -> bool:
    """Kör TUI-post via registry. True = känt nummer (kört).

    Strängflöden slås upp mot tui-modulen och felar högt med kontext om
    namnet inte finns — ett omdöpt flöde får aldrig tystna.
    """
    from shallot_cli import tui
    for cmd in COMMANDS.values():
        if number in cmd.tui:
            _, flow = cmd.tui[number]
            fn = getattr(tui, flow, None) if isinstance(flow, str) else flow
            if not callable(fn):
                raise RuntimeError(
                    "trasig TUI-koppling: flöde %r för %s saknas" % (flow, cmd.name))
            fn()
            return True
    return False


def menu_entries() -> list[tuple[int, str]]:
    """(nummer, label) sorterat — TUI-menyn genereras härifrån."""
    out = []
    for cmd in COMMANDS.values():
        for number, (label, _flow) in cmd.tui.items():
            out.append((int(number), label))
    return sorted(out)


def _simulate_args(parser):
    from shallot_cli.sim import SCENARIOS
    sub = parser.add_subparsers(dest="what", required=True)
    auth = sub.add_parser("auth", help="simulera DEN–PAW challenge-response")
    auth.add_argument("--scenario", required=True, choices=list(SCENARIOS),
                      help="felscenario att simulera")


def _simulate_run(args):
    from shallot_cli import sim
    return sim.run_cli(args.scenario)


def _test_args(parser):
    from shallot_cli.commands import test_cmd
    parser.add_argument("suite", nargs="?", default="all",
                        choices=sorted(test_cmd.SUITES),
                        help="testsvit (default: all)")
    parser.add_argument("--json", action="store_true", help="maskinläsbar output")


def _test_run(args):
    from shallot_cli.commands import test_cmd
    return test_cmd.run_suite(args.suite, as_json=args.json)


def _demo_args(parser):
    sub = parser.add_subparsers(dest="what", required=True)
    sub.add_parser("incident", help="simulerad driftlarmscen som avslöjar SHALLOT CLI")


def _demo_run(args):
    from shallot_cli import incident
    return incident.run_cli()


def _explain_args(parser):
    from shallot_cli.explain import TOPICS
    from shallot_cli.ollama import DEFAULT_MODEL
    parser.add_argument("topic", nargs="?", default=None,
                        help="ämne (%s) eller utelämna med --list" % "|".join(sorted(TOPICS)))
    parser.add_argument("--list", action="store_true", help="lista ämnen")
    parser.add_argument("--ai", action="store_true",
                        help="utveckla med lokal Ollama-modell (endast localhost)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="Ollama-modell (default: %s)" % DEFAULT_MODEL)
    parser.add_argument("--host", default=None,
                        help="Ollama-bas-URL (default: $OLLAMA_HOST eller localhost; endast loopback)")


def _explain_run(args):
    from shallot_cli.commands import explain_cmd
    if args.list or args.topic is None:
        return explain_cmd.run_list()
    return explain_cmd.run(args.topic, ai=args.ai, model=args.model, host=args.host)


def _protocol_args(parser):
    sub = parser.add_subparsers(dest="what", required=True)
    e = sub.add_parser("encode", help="koda payload till ramhex")
    e.add_argument("--type", required=True,
                   help="ramtyp (challenge/response/heartbeat/alarm/ack eller 0x01/...)")
    e.add_argument("--payload", required=True, help="payload som hex (tom sträng för heartbeat)")
    d = sub.add_parser("decode", help="avkoda och validera ramhex")
    d.add_argument("--frame", required=True, help="komplett ram som hex")


def _protocol_run(args):
    from shallot_cli.commands import protocol_cmd
    if args.what == "encode":
        return protocol_cmd.run_encode(args.type, args.payload)
    return protocol_cmd.run_decode(args.frame)


def _doctor_run(args):
    from shallot_cli.commands import doctor_cmd
    return doctor_cmd.run()


def _device_args(parser):
    sub = parser.add_subparsers(dest="what", required=True)
    sub.add_parser("list", help="lista serieportar")


def _device_run(args):
    from shallot_cli.commands import device_cmd
    return device_cmd.run_list()


def _build_args(parser):
    from shallot_cli.commands import build_cmd
    parser.add_argument("target", choices=sorted(build_cmd.TARGETS), help="firmware-mål")
    parser.add_argument("--dry-run", action="store_true",
                        help="visa kommandot utan att köra det (enda läget som stöds)")


def _build_run(args):
    from shallot_cli.commands import build_cmd
    return build_cmd.run(args.target, dry_run=args.dry_run)


def _monitor_args(parser):
    from shallot_cli.commands import monitor_cmd
    parser.add_argument("--device", required=True, choices=list(monitor_cmd.DEVICES),
                        help="vilken enhet loggen förväntas komma från")
    parser.add_argument("--port", required=True, help="serieport (t.ex. /dev/ttyACM0)")
    parser.add_argument("--baud", type=int, default=115200, help="baudrate (default: 115200)")


def _monitor_run(args):
    from shallot_cli.commands import monitor_cmd
    return monitor_cmd.run(args.device, args.port, baud=args.baud)


def _mamabear_args(parser):
    sub = parser.add_subparsers(dest="what", required=True)
    mbs = sub.add_parser("status", help="läsande statuskontroll på MamaBear")
    mbs.add_argument("--host", required=True,
                     help="ssh-alias från ~/.ssh/config (aldrig adress, user@värd eller nyckel)")
    mbs.add_argument("--yes", action="store_true",
                     help="bekräfta SSH-anslutning utan interaktiv fråga")
    mbt = sub.add_parser("test", help="läsande självtest på MamaBear, sparar JSON-resultat")
    mbt.add_argument("--host", required=True,
                     help="ssh-alias från ~/.ssh/config (aldrig adress, user@värd eller nyckel)")
    mbt.add_argument("--output", default=None,
                     help="lokal resultatfil (default: mamabear-test-<tid>.json)")
    mbt.add_argument("--yes", action="store_true",
                     help="bekräfta SSH-anslutning utan interaktiv fråga")


def _mamabear_run(args):
    from shallot_cli.commands import mamabear_cmd
    if args.what == "status":
        return mamabear_cmd.run_status(args.host, yes=args.yes)
    return mamabear_cmd.run_test(args.host, yes=args.yes, output=args.output)


def _fido2_args(parser):
    from shallot_cli.fido2 import SCENARIOS as FIDO2_SCENARIOS
    from shallot_cli.fido2 import UV_POLICIES
    sub = parser.add_subparsers(dest="what", required=True)
    f2r = sub.add_parser("register", help="registrera credential för användare")
    f2r.add_argument("--user", required=True, help="anonymt användar-ID (t.ex. admin-01)")
    f2r.add_argument("--yes", action="store_true",
                     help="bekräfta registrering utan interaktiv fråga")
    f2r.add_argument("--mock", action="store_true",
                     help="mock-authenticator istället för fysisk (explicit testläge, SIMULATED / TEST-ONLY)")
    f2r.add_argument("--require-uv", action="store_true",
                     help="kräv PIN/biometri (user verification), lagras i policyn")
    f2a = sub.add_parser("authenticate", help="verifiera assertion (ALLOW/DENY)")
    f2a.add_argument("--user", required=True, help="anonymt användar-ID")
    f2a.add_argument("--credential", default=None,
                     help="credential-ID (default: användarens aktiva credential)")
    f2a.add_argument("--mock", action="store_true",
                     help="mock-authenticator istället för fysisk (explicit testläge, SIMULATED / TEST-ONLY)")
    f2a.add_argument("--require-uv", action="store_true",
                     help="kräv PIN/biometri för detta beslut (fail closed utan UV-flagg)")
    f2c = sub.add_parser("credential", help="administrera credentials")
    f2csub = f2c.add_subparsers(dest="op", required=True)
    f2csub.add_parser("list", help="lista credentials (sanerat)")
    f2cv = f2csub.add_parser("revoke", help="spärra credential (kräver bekräftelse)")
    f2cv.add_argument("--credential", required=True, help="credential-ID")
    f2cv.add_argument("--yes", action="store_true",
                      help="bekräfta spärrning utan interaktiv fråga")
    f2cs = f2csub.add_parser("status", help="visa credential-status (sanerat)")
    f2cs.add_argument("--credential", required=True, help="credential-ID")
    f2ce = f2csub.add_parser("export", help="exportera publik metadata för MamaBear-godkännande")
    f2ce.add_argument("--credential", required=True, help="credential-ID")
    f2ce.add_argument("--output", required=True, help="lokal målfil (JSON)")
    f2cp = f2csub.add_parser("set-policy", help="ändra UV-policy (kräver bekräftelse)")
    f2cp.add_argument("--credential", required=True, help="credential-ID")
    f2cp.add_argument("--user-verification", required=True, choices=list(UV_POLICIES),
                      help="ny UV-policy: required|preferred|discouraged")
    f2cp.add_argument("--yes", action="store_true",
                      help="bekräfta policyändring utan interaktiv fråga")
    f2s = sub.add_parser("simulate", help="deterministisk FIDO2-simulering (TEST-ONLY)")
    f2s.add_argument("--scenario", required=True, choices=list(FIDO2_SCENARIOS),
                     help="scenario att simulera")
    f2u = sub.add_parser("audit", help="visa senaste auditposter")
    f2u.add_argument("--limit", type=int, default=20,
                     help="antal poster (default: 20)")
    f2d = sub.add_parser("device", help="fysiska CTAP-enheter (skrivfritt)")
    f2dsub = f2d.add_subparsers(dest="devop", required=True)
    f2dsub.add_parser("list", help="lista anslutna FIDO2-authenticators")


def _fido2_run(args):
    from shallot_cli.commands import fido2_cmd
    if args.what == "register":
        return fido2_cmd.run_register(args.user, yes=args.yes, mock=args.mock,
                                       require_uv=args.require_uv)
    if args.what == "authenticate":
        return fido2_cmd.run_authenticate(args.user, credential=args.credential,
                                           mock=args.mock,
                                           require_uv=args.require_uv)
    if args.what == "credential":
        if args.op == "list":
            return fido2_cmd.run_credential_list()
        if args.op == "revoke":
            return fido2_cmd.run_credential_revoke(args.credential, yes=args.yes)
        if args.op == "export":
            return fido2_cmd.run_credential_export(args.credential, args.output)
        if args.op == "set-policy":
            return fido2_cmd.run_credential_set_policy(
                args.credential, args.user_verification, yes=args.yes)
        return fido2_cmd.run_credential_status(args.credential)
    if args.what == "device":
        return fido2_cmd.run_device_list()
    if args.what == "audit":
        if args.limit <= 0:
            print("error: --limit måste vara positivt.", file=sys.stderr)
            return 2
        return fido2_cmd.run_audit(limit=args.limit)
    return fido2_cmd.run_simulate(args.scenario)


def _direct_run_list():
    from shallot_cli.commands import device_cmd
    return device_cmd.run_list()


def _direct_fido2_list():
    from shallot_cli.commands import fido2_cmd
    return fido2_cmd.run_credential_list()


def _direct_fido2_audit():
    from shallot_cli.commands import fido2_cmd
    return fido2_cmd.run_audit()


def _direct_fido2_devices():
    from shallot_cli.commands import fido2_cmd
    return fido2_cmd.run_device_list()


register(Command(
    name="test", help_text="kör befintliga pytest-sviter",
    add_arguments=_test_args, run=_test_run,
    tui={"1": ("Kör tester (alla sviter)", "_flow_test_all"),
         "2": ("Kör en testsvit (välj)", "_flow_test_suite")},
))

register(Command(
    name="simulate", help_text="deterministisk simulering (TEST-ONLY)",
    add_arguments=_simulate_args, run=_simulate_run,
    tui={"3": ("Simulera autentisering (SIMULATED / TEST-ONLY)", "_flow_simulate")},
))

register(Command(
    name="demo", help_text="simulerad incident för presentation (SIMULERING)",
    add_arguments=_demo_args, run=_demo_run,
    tui={"20": ("Simulerad incident (SIMULERING)", "_flow_demo"),
         "26": ("Demo: presentation (tester + fysisk bänk)", "_flow_demo_presentation")},
))

register(Command(
    name="explain", help_text="lokal förklaring av begrepp (offline; --ai via Ollama)",
    add_arguments=_explain_args, run=_explain_run,
    tui={"21": ("Förklara begrepp (offline)", "_flow_explain")},
))

register(Command(
    name="protocol", help_text="UART-ramformatet (utan hårdvara)",
    add_arguments=_protocol_args, run=_protocol_run,
    tui={"4": ("Protokoll: encode (payload -> ram)", "_flow_encode"),
         "5": ("Protokoll: decode (ram -> payload)", "_flow_decode")},
))

register(Command(
    name="doctor", help_text="skrivfri miljökontroll",
    add_arguments=lambda parser: None, run=_doctor_run,
    tui={"6": ("Diagnostik (doctor)", "_flow_doctor")},
))

register(Command(
    name="build", help_text="visa (aldrig köra) byggkommandon",
    add_arguments=_build_args, run=_build_run,
    tui={"7": ("Build dry-run (visar endast, bygger aldrig)", "_flow_build")},
))

register(Command(
    name="device", help_text="serieportar (skrivfritt)",
    add_arguments=_device_args, run=_device_run,
    tui={"8": ("Lista enheter (skrivfritt)", _direct_run_list)},
))

register(Command(
    name="monitor", help_text="skrivskyddad visning av serial-loggar",
    add_arguments=_monitor_args, run=_monitor_run,
    tui={"9": ("Monitorera port (skrivskyddad läsning)", "_flow_monitor")},
))

register(Command(
    name="mamabear", help_text="läsande MamaBear-fjärrläge över system-SSH",
    add_arguments=_mamabear_args, run=_mamabear_run,
    tui={"10": ("MamaBear fjärrläge (läsande, bekräftas)", "_flow_mamabear")},
))

def _admin_args(parser):
    sub = parser.add_subparsers(dest="what", required=True)
    a_in = sub.add_parser("login", help="interaktiv Admin-inloggning (FIDO2 + installationskod)")
    a_in.add_argument("--user", required=True, help="anonymt användar-ID (t.ex. admin-01)")
    a_in.add_argument("--credential", default=None, help="credential-ID (default: användarens aktiva credential)")
    a_in.add_argument("--mock", action="store_true",
                      help="mock-authenticator istället för fysisk (explicit testläge, SIMULATED / TEST-ONLY)")
    sub.add_parser("logout", help="avsluta Admin-session")
    sub.add_parser("status", help="visa sessionsstatus (0 = giltig session)")
    a_rst = sub.add_parser("reset-code", help="fysisk återställning: skapa ny installationskod")
    a_rst.add_argument("--confirm", action="store_true",
                       help="bekräfta återställning (krävs)")


def _admin_run(args):
    from shallot_cli.commands import admin_cmd
    if args.what == "login":
        return admin_cmd.run_login(args.user, credential=args.credential,
                                   mock=args.mock)
    if args.what == "logout":
        return admin_cmd.run_logout()
    if args.what == "status":
        return admin_cmd.run_status()
    return admin_cmd.run_reset_code(confirm=args.confirm)


register(Command(
    name="admin", help_text="Admin-upplevelse (FIDO2 + installationskod)",
    add_arguments=_admin_args, run=_admin_run,
    tui={"22": ("Admin: logga in (FIDO2 + installationskod)", "_flow_admin_login"),
         "23": ("Admin: status", "_flow_admin_status"),
         "24": ("Admin: logga ut", "_flow_admin_logout"),
         "25": ("Admin: fysisk återställning av installationskod", "_flow_admin_reset")},
))

register(Command(
    name="fido2", help_text="FIDO2-härdningsspår (PoC, mock som standard)",
    add_arguments=_fido2_args, run=_fido2_run,
    tui={"11": ("FIDO2: registrera (bekräftas, SIMULATED / TEST-ONLY)", "_flow_fido2_register"),
         "12": ("FIDO2: autentisera (ALLOW/DENY)", "_flow_fido2_authenticate"),
         "13": ("FIDO2: lista credentials", _direct_fido2_list),
         "14": ("FIDO2: spärra credential (bekräftas)", "_flow_fido2_revoke"),
         "15": ("FIDO2: simulera scenario", "_flow_fido2_simulate"),
         "16": ("FIDO2: visa audit", _direct_fido2_audit),
         "17": ("FIDO2: lista anslutna enheter (skrivfritt)", _direct_fido2_devices),
         "18": ("FIDO2: exportera credential för MamaBear-godkännande", "_flow_fido2_export"),
         "19": ("FIDO2: ändra UV-policy (bekräftas)", "_flow_fido2_set_policy")},
))
