"""Interaktivt TUI-läge för `shallot` (startas utan argument).

TUI:t är ett tunt skal över befintliga kommandoimplementationer i
``shallot_cli.commands`` — ingen logik dupliceras här. All
hårdvarunära påverkan kräver bekräftelse (i praktiken: `monitor`,
som öppnar en serieport; allt annat är hårdvarufritt). Simuleringar
märks alltid SIMULATED / TEST-ONLY (via ``sim.render``).
"""

from __future__ import annotations

import sys

from shallot_cli import (
    admin,
    bench,
    demo,
    explain,
    fido2,
    fido2_sanitize,
    incident,
    ollama,
    provision,
    registry,
    serial_adapters,
    sim,
    theme,
    uart,
)
from shallot_cli.commands import (
    admin_cmd,
    build_cmd,
    doctor_cmd,
    explain_cmd,
    fido2_cmd,
    mamabear_cmd,
    monitor_cmd,
    protocol_cmd,
    test_cmd,
)

HEADER = r"""
 ███████╗██╗  ██╗ █████╗ ██╗     ██╗      ██████╗ ████████╗
 ██╔════╝██║  ██║██╔══██╗██║     ██║     ██╔═══██╗╚══██╔══╝
 ███████╗███████║███████║██║     ██║     ██║   ██║   ██║
 ╚════██║██╔══██║██╔══██║██║     ██║     ██║   ██║   ██║
 ███████║██║  ██║██║  ██║███████╗███████╗╚██████╔╝   ██║
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝    ╚═╝
""".strip("\n")

SHALLOT_ONION = r"""
=+
  *=@@@@@%%%+%%%%%%%%==+%%%%%%%%=*    :*@@@+     +%%%%%%%=    :+%%%%%%%=        :**%@@@@%%+:-++%%%%%%%%%%%%%%%%
-%@@==*=%@@%=*+%@@@==-**++%@@@==**    *@@@@%     :+=%@@%++    :-+=@@@=+:      -*=@@%==*=%@@%=+*%@====%@@%===%@@
=@@@%==* +*:::.=@@@%==   .=@@@%=     -%@%@@@*      +%@@=        -*%@@=       +*%@@*   ::+=@@@%*%=-+++%@@=++-*=%
*%@@@@@@=*+    =@@@%==   .=@@@%=    :%@@*%@@@*     +%@@=        -*%@@=      ++%@@%     ---=@@@   -+++%@@=::
 -=%@@@@@@@@%+ =@@@@@@%%%%@@@@%=    *@@%**@@@@     +%@@=        -*%@@=     :+*%@@+     -++*%@@+  -+++%@@=
    -=%%@@@@@@%=@@%===****%@@@%=   -%@@%==%@@@*    +%@@=        -*%@@=     -+*%@@=     :++*%@@+  -+++%@@=
 +++++ -*%@@@%%=@@@%==   .=@@@%=  :%@@%%%%%%@@@*   +%@@=        -*%@@=      +-%@@=     +++=%@@   -+++%@@=
%@@@@@%+ =@@@===@@@%==   .=@@@%=  *@@@=:   *@@@@+  +%@@=    :*%%-*%@@=   :+*%**%@@=   -++=%@@+   -+++%@@=
=@@@@@@@%@@%*+*=@@@%%%*- +=@@@%%**%@@%=*  ++%@@@%***%@@%%%%%%%@@*=%@@%%%%%=%@%-*%@@@%%%%%@@%-  ++****%@@=+
-=%%%@%%%=*.:%@%%%@@@%==%@%%%@@%@@%%@@@%- =@%%%@@@@@%%%%%%%%%%@%@@%%%%%%%%%%@+..-=%%%@@%%=+    +++=%@%%%@@@
   .--::     ........-  ...............   ...................................      .--::         :.........
""".strip("\n")


def _menu_max() -> int:
    """Högsta menynummer — genereras från registryt."""
    return max(n for n, _label in registry.menu_entries())


def _menu_text() -> str:
    lines = [
        theme.orange(" %d  %s" % (n, label)) for n, label in registry.menu_entries()
    ]
    lines.append(theme.orange(" 0  Avsluta"))
    return "\n".join(lines)


def confirm(prompt: str) -> bool:
    """Ja/nej-fråga, default nej. Returnerar True endast vid jakande svar."""
    ans = input("%s [j/N]: " % prompt).strip().lower()
    return ans in ("j", "ja", "y", "yes")


def report(rc: int) -> None:
    """Tydlig statusrad när ett kommando inte lyckades."""
    if rc != 0:
        print("Kommandot avslutades med kod %d." % rc)


class _ArrowCancel(Exception):
    """Piltangentsval avbrutet (q/Esc) — tillbaka utan extra prompt."""


def _arrow_pick(display: list[str]) -> int | None:
    """Välj rad med ↑/↓ + Enter. Returnerar index eller None.

    None = ingen interaktiv terminal (anroparen faller tillbaka på
    sifferval). q/Esc höjer _ArrowCancel. Terminalen återställs alltid.
    Endast POSIX + TTY; Windows/pipe/test → None.
    """
    import os
    import sys

    if not display or os.name != "posix":
        return None
    stdin, stdout = sys.stdin, sys.stdout
    if not stdin.isatty() or not stdout.isatty():
        return None
    try:
        import select
        import termios
    except ImportError:
        return None
    fd = stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except Exception:
        return None
    selected = 0
    n = len(display)
    hint = "\u2191 \u2193 navigera \u00b7 Enter v\u00e4lj \u00b7 q avbryt"

    def render():
        out = []
        for i, line in enumerate(display):
            prefix = "\u25b6 " if i == selected else "  "
            text = prefix + line
            out.append(
                "\r\x1b[K%s"
                % (theme.accent(text) if i == selected else theme.orange(text))
            )
        out.append("\r\x1b[K%s" % theme.dim(hint))
        stdout.write("\n".join(out) + "\n")
        stdout.flush()

    def read_key():
        ch = os.read(fd, 1).decode("utf-8", errors="replace")
        if ch != "\x1b":
            return ch
        r, _, _ = select.select([fd], [], [], 0.05)
        if not r:
            return "ESC"
        nxt = os.read(fd, 1).decode("utf-8", errors="replace")
        if nxt not in ("[", "O"):
            return "ESC"
        code = os.read(fd, 1).decode("utf-8", errors="replace")
        return {"A": "UP", "B": "DOWN"}.get(code, "OTHER")

    stdout.write("\x1b[?25l")
    stdout.flush()
    try:
        # Som tty.setraw, men TCSANOW: TCSADRAIN kan blockera på dränering.
        raw = termios.tcgetattr(fd)
        raw[0] = raw[0] & ~(
            termios.BRKINT
            | termios.ICRNL
            | termios.INPCK
            | termios.ISTRIP
            | termios.IXON
        )
        raw[1] = raw[1] & ~termios.OPOST
        raw[2] = raw[2] & ~(termios.CSIZE | termios.PARENB)
        raw[2] = raw[2] | termios.CS8
        raw[3] = raw[3] & ~(
            termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG
        )
        raw[6][termios.VMIN] = 1
        raw[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, raw)
        for i, line in enumerate(display):
            prefix = "\u25b6 " if i == selected else "  "
            stdout.write(
                "%s\n"
                % (
                    theme.accent(prefix + line)
                    if i == selected
                    else theme.orange(prefix + line)
                )
            )
        stdout.write("%s\n" % theme.dim(hint))
        stdout.flush()
        while True:
            stdout.write("\x1b[%dA" % (n + 1))
            render()
            key = read_key()
            if key in ("\r", "\n"):
                return selected
            if key in ("q", "Q", "ESC"):
                raise _ArrowCancel
            if key == "UP":
                selected = (selected - 1) % n
            elif key == "DOWN":
                selected = (selected + 1) % n
            elif key == "\x03":
                raise KeyboardInterrupt
    finally:
        # TCSANOW, aldrig TCSADRAIN: cleanup får inte blockera på dränering.
        termios.tcsetattr(fd, termios.TCSANOW, old)
        stdout.write("\x1b[?25h\n")
        stdout.flush()


def _pick(title: str, options: list[str]) -> str | None:
    """Underval med piltangenter (fallback: sifferval). None = tillbaka."""
    print(title)
    lines = ["  %d  %s" % (i, opt) for i, opt in enumerate(options, 1)]
    try:
        idx = _arrow_pick(lines)
    except _ArrowCancel:
        return None
    if idx is not None:
        return options[idx]
    for line in lines:
        print(theme.orange(line))
    ans = input("Välj [1-%d]: " % len(options)).strip()
    if not ans.isdigit() or not 1 <= int(ans) <= len(options):
        print("Ogiltigt val: %r. Tillbaka i huvudmenyn." % ans)
        return None
    return options[int(ans) - 1]


def _flow_test_all() -> None:
    report(test_cmd.run_suite("all"))


def _flow_test_suite() -> None:
    suite = _pick("Testsyviter:", sorted(test_cmd.SUITES))
    if suite is None:
        return
    report(test_cmd.run_suite(suite))


def _flow_simulate() -> None:
    print("Deterministisk simulering — SIMULATED / TEST-ONLY.")
    print("Ingen fysisk hårdvara styrs eller verifieras.")
    scenario = _pick("Scenarier:", list(sim.SCENARIOS))
    if scenario is None:
        return
    report(sim.run_cli(scenario))


def _flow_encode() -> None:
    print("Kända ramtyper: %s" % ", ".join(sorted(uart.TYPE_NAMES.values())))
    type_text = input("Ramtyp: ").strip()
    payload_hex = input("Payload som hex (tomt för heartbeat): ").strip()
    report(protocol_cmd.run_encode(type_text, payload_hex))


def _flow_decode() -> None:
    frame_hex = input("Ram som hex: ").strip()
    report(protocol_cmd.run_decode(frame_hex))


def _flow_doctor() -> None:
    report(doctor_cmd.run())


def _flow_demo() -> None:
    print("Simulerad incident — SIMULERING.")
    report(incident.run_cli())


def _flow_demo_precheck() -> None:
    print("Förkontroll av breadboard-riggen (skrivfritt).")
    demo.run_precheck_cli(mock=_pick_mock())


def _flow_demo_breadboard() -> None:
    """Meny -> DEMO -> Starta demo: fysisk 60-sek breadboard-demo.

    Fysisk FIDO2 är standard; mock kräver uttryckligt val och märks
    SIMULATED / TEST-ONLY i hela flödet.
    """
    mock = _pick_mock()
    demo.run_demo(mock=mock)


def _flow_demo_latest() -> None:
    demo.show_latest()


def _flow_bench_list() -> None:
    bench.run_list()


def _flow_bench_verify() -> None:
    bench.run_verify()


def _flow_bench_latest() -> None:
    bench.show_latest()


def _flow_bench_identify() -> None:
    bench.run_identify()


def _flow_bench_unoq() -> None:
    port = input("UNO Q-port (t.ex. /dev/cu.usbmodemXXXX): ").strip()
    cmd = (
        input("Kommando (s=status, g=generera, 1=till DEN, 2=till PAW): ")
        .strip()
        .lower()
    )
    try:
        report(bench.run_unoq(port, cmd))
    except ValueError as e:
        print("error: %s" % e)


DEMO_SUITES = ("protocol", "den", "paw")
DEMO_DEN_NEEDLES = ("[DEN] AUTHENTICATED (code 0)", "[DEN] FAILED: ")
DEMO_PAW_NEEDLES = (
    "[PRO-84] DEN acknowledged success",
    "[PRO-84] DEN denied (ACK 0x00)",
)
DEMO_OBSERVE_TIMEOUT_S = 60.0


class _DemoAbort(Exception):
    """Avbruten presentation — anroparen skriver orsak, inget mer."""


def _demo_pause(label: str = "Tryck Enter för nästa akt...") -> None:
    try:
        input(label)
    except (EOFError, KeyboardInterrupt):
        raise _DemoAbort("avbrutet av presentatören")


def _demo_pick_port(role: str) -> str:
    ports = [p["device"] for p in serial_adapters.list_ports()]
    if not ports:
        raise _DemoAbort("inga serieportar hittades")
    sel = _pick("%s-port:" % role, ports)
    if sel is None:
        raise _DemoAbort("ingen port vald")
    return sel


def _demo_provision(role: str, port: str, target: str) -> None:
    try:
        ser = serial_adapters.open_provision(port)
    except Exception as e:
        raise _DemoAbort("kunde inte öppna %s: %s" % (port, e))
    entries: list = []
    try:
        with ser:
            res = provision.provision_device(ser, target, audit=entries)
    except provision.ProvisionError as e:
        for entry in entries:
            admin.audit_admin(entry["action"], entry["details"])
        raise _DemoAbort("%s nekar provisionering: %s" % (role, e))
    except Exception as e:
        raise _DemoAbort("%s fel vid provisionering: %s" % (role, e))
    for entry in entries:
        admin.audit_admin(entry["action"], entry["details"])
    print("%s provisionerad (fingeravtryck %s)." % (role, res["fingerprint"].hex()))


def _flow_demo_presentation() -> None:
    """Meny -> DEMO -> Starta demo: tester, sedan fysisk bänk."""
    try:
        print("SHALLOT demo — Akt 1: automatiska tester.")
        for suite in DEMO_SUITES:
            if test_cmd.run_suite(suite) != 0:
                print("Demot avbryts: rött testresultat.")
                return
        _demo_pause()
        print("Akt 2: fysisk bänk (FIDO2 -> PAW -> DEN).")
        user = input("Admin-användare: ").strip()
        if not user:
            print("Ingen användare angiven. Demot avbryts.")
            return
        if admin_cmd.run_login(user) != 0:
            print("Demot avbryts: inloggning nekad.")
            return
        try:
            admin.require_session("provision")
        except admin.AdminDenied as e:
            print("Demot avbryts: %s" % e)
            return
        paw_port = _demo_pick_port("PAW")
        den_port = _demo_pick_port("DEN")
        _demo_provision("PAW", paw_port, "paw")
        _demo_provision("DEN", den_port, "den")
        print("Starta om eller docka enheterna för handshake.")
        den_hit, den_line = monitor_cmd.read_until(
            den_port, 115200, list(DEMO_DEN_NEEDLES), DEMO_OBSERVE_TIMEOUT_S
        )
        paw_hit, paw_line = monitor_cmd.read_until(
            paw_port, 115200, list(DEMO_PAW_NEEDLES), DEMO_OBSERVE_TIMEOUT_S
        )
        for line in (den_line, paw_line):
            if line:
                print("logg: %s" % fido2_sanitize.sanitize(line))
        manual = confirm("Visar PAW-displayen AUTHENTICATED?")
        grant = (
            den_hit == DEMO_DEN_NEEDLES[0] and paw_hit == DEMO_PAW_NEEDLES[0] and manual
        )
        admin.audit_admin(
            "demo-verdict", {"result": "GODKÄND" if grant else "UNDERKÄND"}
        )
        if grant:
            print("Demo: GODKÄND.")
        else:
            print("Demo: UNDERKÄND (logg och display oense eller timeout).")
        report(0 if grant else 1)
    except _DemoAbort as e:
        print("Demo avbrutet: %s" % e)
        return


def _flow_explain() -> None:
    topic = _pick("Ämnen:", explain.topic_names())
    if topic is None:
        return
    use_ai = confirm("Utveckla med lokal Ollama-modell")
    model = host = None
    if use_ai:
        model = (
            input("Ollama-modell (tomt = %s): " % ollama.DEFAULT_MODEL).strip() or None
        )
        host = input("Ollama-host (tomt = localhost): ").strip() or None
    report(
        explain_cmd.run(
            topic, ai=use_ai, model=model or ollama.DEFAULT_MODEL, host=host
        )
    )


def _flow_build() -> None:
    target = _pick(
        "Firmware-mål (endast dry-run — inget byggs):", sorted(build_cmd.TARGETS)
    )
    if target is None:
        return
    report(build_cmd.run(target, dry_run=True))


def _flow_mamabear() -> None:
    what = _pick(
        "MamaBear fjärrläge (läsande — ingen skrivning på MamaBear):",
        ["status", "test"],
    )
    if what is None:
        return
    host = input("SSH-alias från ~/.ssh/config: ").strip()
    if what == "status":
        report(mamabear_cmd.run_status(host, confirm=confirm))
    else:
        output = input("Resultatfil (tomt = standard): ").strip() or None
        report(mamabear_cmd.run_test(host, confirm=confirm, output=output))


def _pick_mock() -> bool:
    """Fråga fysisk vs mock. Returnerar True för mock (explicit testval).

    Standardläge är fysisk authenticator — mock kräver att användaren
    aktivt väljer det och märks SIMULATED / TEST-ONLY nedströms.
    """
    choice = input("Authenticator [fysisk/mock] (default fysisk): ").strip().lower()
    if choice in ("mock", "m", "test"):
        print("Mock-läge valt (SIMULATED / TEST-ONLY).")
        return True
    print("HARDWARE — fysisk authenticator via CTAP2/HID. Rör vid enheten vid prompt.")
    return False


def _flow_fido2_register() -> None:
    user = input("Användar-ID (t.ex. admin-01): ").strip()
    mock = _pick_mock()
    require_uv = confirm("Kräv PIN/biometri (user verification)")
    report(
        fido2_cmd.run_register(user, mock=mock, require_uv=require_uv, confirm=confirm)
    )


def _flow_fido2_authenticate() -> None:
    user = input("Användar-ID: ").strip()
    credential = input("Credential-ID (tomt = aktiv credential): ").strip() or None
    mock = _pick_mock()
    require_uv = confirm("Kräv PIN/biometri för detta beslut")
    report(
        fido2_cmd.run_authenticate(
            user, credential=credential, mock=mock, require_uv=require_uv
        )
    )


def _flow_fido2_simulate() -> None:
    print("Deterministisk FIDO2-simulering — SIMULATED / TEST-ONLY.")
    scenario = _pick("Scenarier:", list(fido2.SCENARIOS))
    if scenario is None:
        return
    report(fido2_cmd.run_simulate(scenario))


def _flow_fido2_revoke() -> None:
    credential = input("Credential-ID att spärra: ").strip()
    if not credential:
        print("Inget credential angivet. Tillbaka i huvudmenyn.")
        return
    report(fido2_cmd.run_credential_revoke(credential, confirm=confirm))


def _flow_fido2_set_policy() -> None:
    credential = input("Credential-ID: ").strip()
    if not credential:
        print("Inget credential angivet. Tillbaka i huvudmenyn.")
        return
    policy = _pick("Ny UV-policy:", list(fido2.UV_POLICIES))
    if policy is None:
        return
    report(fido2_cmd.run_credential_set_policy(credential, policy, confirm=confirm))


def _flow_fido2_export() -> None:
    print("Exporterar endast publik metadata (aldrig hemligheter).")
    credential = input("Credential-ID att exportera: ").strip()
    if not credential:
        print("Inget credential angivet. Tillbaka i huvudmenyn.")
        return
    output = input("Målfil (t.ex. admin-01.approval.json): ").strip()
    if not output:
        print("Ingen målfil angiven. Tillbaka i huvudmenyn.")
        return
    report(fido2_cmd.run_credential_export(credential, output))


def _flow_admin_login() -> None:
    user = input("Admin-användare (t.ex. admin-01): ").strip()
    if not user:
        print("Ingen användare angiven. Tillbaka i huvudmenyn.")
        return
    mock = _pick_mock()
    credential = input("Credential-ID (tomt = aktiv credential): ").strip() or None
    report(admin_cmd.run_login(user, credential=credential, mock=mock))


def _flow_admin_status() -> None:
    report(admin_cmd.run_status())


def _flow_admin_logout() -> None:
    report(admin_cmd.run_logout())


def _flow_admin_reset() -> None:
    print("Fysisk återställning skapar en ny installationskod.")
    print("Kräver färsk beröring av fysisk authenticator.")
    if not confirm("Fortsätt med fysisk återställning"):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    report(admin_cmd.run_reset_code(confirm=True))


def _flow_monitor() -> None:
    device = _pick("Enhet:", list(monitor_cmd.DEVICES))
    if device is None:
        return
    ports = [p["device"] for p in serial_adapters.list_ports()]
    if ports:
        print("Hittade portar: %s" % ", ".join(ports))
    port = input("Port%s: " % (" (tomt = %s)" % ports[0] if ports else "")).strip()
    if not port:
        if not ports:
            print("Ingen port angiven och inga portar hittades. Tillbaka i huvudmenyn.")
            return
        port = ports[0]
    print(
        "Monitor öppnar %s för läsning. Skriver aldrig till enheten; "
        "kan inte styra den." % port
    )
    if not confirm("Fortsätt med skrivskyddad läsning av %s" % port):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    baud_raw = input("Baudrate (tomt = 115200): ").strip()
    try:
        baud = int(baud_raw) if baud_raw else 115200
    except ValueError:
        print("Ogiltig baudrate. Tillbaka i huvudmenyn.")
        return
    report(monitor_cmd.run(device, port, baud=baud))


def handle_choice(choice: str) -> bool:
    """Utför ett menyval. Returnerar True om TUI:t ska avslutas."""
    if choice == "0":
        print("Avslutar.")
        return True
    if registry.dispatch_tui(choice):
        return False
    print("Ogiltigt val: %r. Välj 0–%d." % (choice, _menu_max()))
    return False


def _menu_choice() -> str | None:
    """Huvudmenyval med piltangenter (fallback: siffror). None = avbrutet."""
    numbered = [(n, label) for n, label in registry.menu_entries()]
    numbered.append((0, "Avsluta"))
    lines = [" %d  %s" % (n, label) for n, label in numbered]
    print()
    try:
        idx = _arrow_pick(lines)
    except _ArrowCancel:
        return None
    if idx is not None:
        return str(numbered[idx][0])
    print(_menu_text())
    return input("Välj [0-%d]: " % _menu_max()).strip()


def run() -> int:
    """Huvudloop. 0 = normalt avslut; Ctrl-C vid menyn avslutar också rent."""
    print(theme.paint(HEADER, theme.ORANGE))
    print(theme.paint(SHALLOT_ONION, theme.ORANGE))
    print("Interaktivt läge. Styr eller verifierar ingen fysisk hårdvara.")
    while True:
        try:
            choice = _menu_choice()
        except KeyboardInterrupt:
            print("\nAvslutar.")
            return 0
        except EOFError:
            print("\nAvslutar (stdin stängd).")
            return 0
        if not choice:
            continue
        try:
            if handle_choice(choice):
                return 0
        except KeyboardInterrupt:
            print("\nAvbrutet med Ctrl-C — tillbaka i menyn.")
        except EOFError:
            print("\nAvslutar (stdin stängd).")
            return 0


if __name__ == "__main__":
    sys.exit(run())
