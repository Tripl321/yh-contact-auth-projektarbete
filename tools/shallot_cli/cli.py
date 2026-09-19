"""shallot — lokal test-/simulerings-CLI för SHALLOT.

Styr eller verifierar ingen fysisk hårdvara. Resultat från `test`
och `simulate` är automatiska tester/simuleringar, inte
hårdvaruverifiering.

Exit-koder: 0 = ok, 1 = fel vid körning/underkända tester,
2 = felaktig användning (ogiltiga argument).

Utan argument startar ett interaktivt TUI-läge (se shallot_cli.tui).
"""

from __future__ import annotations

import argparse
import sys

from shallot_cli.commands import build_cmd, device_cmd, demo_cmd, explain_cmd, fido2_cmd, mamabear_cmd, monitor_cmd, protocol_cmd, test_cmd
from shallot_cli.fido2 import SCENARIOS as FIDO2_SCENARIOS
from shallot_cli.fido2 import UV_POLICIES
from shallot_cli.explain import TOPICS as EXPLAIN_TOPICS
from shallot_cli.sim import SCENARIOS
from shallot_cli import registry
from shallot_cli import tui


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shallot",
        description="Lokal test-/simulerings-CLI för SHALLOT. "
                    "Styr eller verifierar ingen fysisk hårdvara.")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("test", help="kör befintliga pytest-sviter")
    t.add_argument("suite", nargs="?", default="all",
                   choices=sorted(test_cmd.SUITES),
                   help="testsvit (default: all)")
    t.add_argument("--json", action="store_true", help="maskinläsbar output")

    for _cmd in registry.COMMANDS.values():
        _p = sub.add_parser(_cmd.name, help=_cmd.help_text)
        _cmd.add_arguments(_p)

    dm = sub.add_parser("demo", help="simulerad incident för presentation (SIMULERING)")
    dmsub = dm.add_subparsers(dest="what", required=True)
    dmsub.add_parser("incident", help="simulerad driftlarmscen som avslöjar SHALLOT CLI")

    ex = sub.add_parser("explain", help="lokal förklaring av begrepp (offline; --ai via Ollama)")
    ex.add_argument("topic", nargs="?", default=None,
                    help="ämne (%s) eller utelämna med --list" % "|".join(sorted(EXPLAIN_TOPICS)))
    ex.add_argument("--list", action="store_true", help="lista ämnen")
    ex.add_argument("--ai", action="store_true",
                    help="utveckla med lokal Ollama-modell (endast localhost)")
    ex.add_argument("--model", default="llama3.2", help="Ollama-modell (default: llama3.2)")
    ex.add_argument("--host", default=None,
                    help="Ollama-bas-URL (default: $OLLAMA_HOST eller localhost; endast loopback)")

    pr = sub.add_parser("protocol", help="UART-ramformatet (utan hårdvara)")
    prsub = pr.add_subparsers(dest="what", required=True)
    e = prsub.add_parser("encode", help="koda payload till ramhex")
    e.add_argument("--type", required=True, help="ramtyp (challenge/response/heartbeat/alarm/ack eller 0x01/...)")
    e.add_argument("--payload", required=True, help="payload som hex (tom sträng för heartbeat)")
    d = prsub.add_parser("decode", help="avkoda och validera ramhex")
    d.add_argument("--frame", required=True, help="komplett ram som hex")

    # doctor byggs via registry (se ovan).

    b = sub.add_parser("build", help="visa (aldrig köra) byggkommandon")
    b.add_argument("target", choices=sorted(build_cmd.TARGETS), help="firmware-mål")
    b.add_argument("--dry-run", action="store_true",
                   help="visa kommandot utan att köra det (enda läget som stöds)")

    dv = sub.add_parser("device", help="serieportar (skrivfritt)")
    dvsub = dv.add_subparsers(dest="what", required=True)
    dvsub.add_parser("list", help="lista serieportar")

    m = sub.add_parser("monitor", help="skrivskyddad visning av serial-loggar")
    m.add_argument("--device", required=True, choices=list(monitor_cmd.DEVICES),
                   help="vilken enhet loggen förväntas komma från")
    m.add_argument("--port", required=True, help="serieport (t.ex. /dev/ttyACM0)")
    m.add_argument("--baud", type=int, default=115200, help="baudrate (default: 115200)")

    mb = sub.add_parser("mamabear", help="läsande MamaBear-fjärrläge över system-SSH")
    mbsub = mb.add_subparsers(dest="what", required=True)
    mbs = mbsub.add_parser("status", help="läsande statuskontroll på MamaBear")
    mbs.add_argument("--host", required=True,
                     help="ssh-alias från ~/.ssh/config (aldrig adress, user@värd eller nyckel)")
    mbs.add_argument("--yes", action="store_true",
                     help="bekräfta SSH-anslutning utan interaktiv fråga")
    mbt = mbsub.add_parser("test", help="läsande självtest på MamaBear, sparar JSON-resultat")
    mbt.add_argument("--host", required=True,
                     help="ssh-alias från ~/.ssh/config (aldrig adress, user@värd eller nyckel)")
    mbt.add_argument("--output", default=None,
                     help="lokal resultatfil (default: mamabear-test-<tid>.json)")
    mbt.add_argument("--yes", action="store_true",
                     help="bekräfta SSH-anslutning utan interaktiv fråga")

    f2 = sub.add_parser("fido2", help="FIDO2-härdningsspår (PoC, mock som standard)")
    f2sub = f2.add_subparsers(dest="what", required=True)
    f2r = f2sub.add_parser("register", help="registrera credential för användare")
    f2r.add_argument("--user", required=True, help="anonymt användar-ID (t.ex. admin-01)")
    f2r.add_argument("--yes", action="store_true",
                     help="bekräfta registrering utan interaktiv fråga")
    f2r.add_argument("--hardware", action="store_true",
                     help="använd fysisk authenticator över CTAP2/HID (kräver beröring)")
    f2r.add_argument("--require-uv", action="store_true",
                     help="kräv PIN/biometri (user verification), lagras i policyn")
    f2a = f2sub.add_parser("authenticate", help="verifiera assertion (ALLOW/DENY)")
    f2a.add_argument("--user", required=True, help="anonymt användar-ID")
    f2a.add_argument("--credential", default=None,
                     help="credential-ID (default: användarens aktiva credential)")
    f2a.add_argument("--hardware", action="store_true",
                     help="använd fysisk authenticator över CTAP2/HID (kräver beröring)")
    f2a.add_argument("--require-uv", action="store_true",
                     help="kräv PIN/biometri för detta beslut (fail closed utan UV-flagg)")
    f2c = f2sub.add_parser("credential", help="administrera credentials")
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
    f2s = f2sub.add_parser("simulate", help="deterministisk FIDO2-simulering (TEST-ONLY)")
    f2s.add_argument("--scenario", required=True, choices=list(FIDO2_SCENARIOS),
                     help="scenario att simulera")
    f2d = f2sub.add_parser("device", help="fysiska CTAP-enheter (skrivfritt)")
    f2dsub = f2d.add_subparsers(dest="devop", required=True)
    f2dsub.add_parser("list", help="lista anslutna FIDO2-authenticators")
    return p


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return tui.run()
    args = build_parser().parse_args(argv)
    if args.command in registry.COMMANDS:
        return registry.COMMANDS[args.command].run(args)
    if args.command == "test":
        return test_cmd.run_suite(args.suite, as_json=args.json)
    if args.command == "demo":
        return demo_cmd.run()
    if args.command == "explain":
        if args.list or args.topic is None:
            return explain_cmd.run_list()
        return explain_cmd.run(args.topic, ai=args.ai, model=args.model, host=args.host)
    if args.command == "protocol":
        if args.what == "encode":
            return protocol_cmd.run_encode(args.type, args.payload)
        return protocol_cmd.run_decode(args.frame)
    if args.command == "build":
        return build_cmd.run(args.target, dry_run=args.dry_run)
    if args.command == "device":
        return device_cmd.run_list()
    if args.command == "monitor":
        return monitor_cmd.run(args.device, args.port, baud=args.baud)
    if args.command == "mamabear":
        if args.what == "status":
            return mamabear_cmd.run_status(args.host, yes=args.yes)
        return mamabear_cmd.run_test(args.host, yes=args.yes, output=args.output)
    if args.command == "fido2":
        if args.what == "register":
            return fido2_cmd.run_register(args.user, yes=args.yes, hardware=args.hardware,
                                          require_uv=args.require_uv)
        if args.what == "authenticate":
            return fido2_cmd.run_authenticate(args.user, credential=args.credential,
                                              hardware=args.hardware,
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
        return fido2_cmd.run_simulate(args.scenario)
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
