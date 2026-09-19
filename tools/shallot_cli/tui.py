"""Interaktivt TUI-läge för `shallot` (startas utan argument).

TUI:t är ett tunt skal över befintliga kommandoimplementationer i
``shallot_cli.commands`` — ingen logik dupliceras här. All
hårdvarunära påverkan kräver bekräftelse (i praktiken: `monitor`,
som öppnar en serieport; allt annat är hårdvarufritt). Simuleringar
märks alltid SIMULATED / TEST-ONLY (via ``sim.render``).
"""

from __future__ import annotations

import sys

from shallot_cli import fido2, registry, serial_adapters, sim, uart
from shallot_cli.commands import (
    build_cmd,
    device_cmd,
    fido2_cmd,
    mamabear_cmd,
    monitor_cmd,
    protocol_cmd,
    simulate_cmd,
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

MENU = """\
1  Kör tester (alla sviter)
2  Kör en testsvit (välj)
3  Simulera autentisering (SIMULATED / TEST-ONLY)
4  Protokoll: encode (payload -> ram)
5  Protokoll: decode (ram -> payload)
6  Diagnostik (doctor)
7  Build dry-run (visar endast, bygger aldrig)
8  Lista enheter (skrivfritt)
9  Monitorera port (skrivskyddad läsning)
10 MamaBear fjärrläge (läsande, bekräftas)
11 FIDO2: registrera (bekräftas, SIMULATED / TEST-ONLY)
12 FIDO2: autentisera (ALLOW/DENY)
13 FIDO2: lista credentials
14 FIDO2: spärra credential (bekräftas)
15 FIDO2: simulera scenario
16 FIDO2: visa audit
17 FIDO2: lista anslutna enheter (skrivfritt)
18 FIDO2: exportera credential för MamaBear-godkännande
19 FIDO2: ändra UV-policy (bekräftas)
0  Avsluta"""


def confirm(prompt: str) -> bool:
    """Ja/nej-fråga, default nej. Returnerar True endast vid jakande svar."""
    ans = input("%s [j/N]: " % prompt).strip().lower()
    return ans in ("j", "ja", "y", "yes")


def report(rc: int) -> None:
    """Tydlig statusrad när ett kommando inte lyckades."""
    if rc != 0:
        print("Kommandot avslutades med kod %d." % rc)


def _pick(title: str, options: list[str]) -> str | None:
    """Numrerat underval. Returnerar valt alternativ eller None vid fel."""
    print(title)
    for i, opt in enumerate(options, 1):
        print("  %d  %s" % (i, opt))
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
    report(simulate_cmd.run(scenario))


def _flow_encode() -> None:
    print("Kända ramtyper: %s" % ", ".join(sorted(uart.TYPE_NAMES.values())))
    type_text = input("Ramtyp: ").strip()
    payload_hex = input("Payload som hex (tomt för heartbeat): ").strip()
    report(protocol_cmd.run_encode(type_text, payload_hex))


def _flow_decode() -> None:
    frame_hex = input("Ram som hex: ").strip()
    report(protocol_cmd.run_decode(frame_hex))


def _flow_build() -> None:
    target = _pick("Firmware-mål (endast dry-run — inget byggs):",
                   sorted(build_cmd.TARGETS))
    if target is None:
        return
    report(build_cmd.run(target, dry_run=True))


def _flow_mamabear() -> None:
    what = _pick("MamaBear fjärrläge (läsande — ingen skrivning på MamaBear):",
                 ["status", "test"])
    if what is None:
        return
    host = input("SSH-alias från ~/.ssh/config: ").strip()
    print("SSH-anslutning till '%s' via system-ssh. Kör endast läsande "
          "kommandon; inget skrivs på MamaBear." % host)
    if not confirm("Fortsätt med SSH-anslutning"):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    if what == "status":
        report(mamabear_cmd.run_status(host, yes=True))
    else:
        report(mamabear_cmd.run_test(host, yes=True))


def _pick_backend() -> bool:
    """Fråga mock vs hardware. Returnerar True för hardware (explicit val)."""
    choice = input("Authenticator [mock/hardware] (default mock): ").strip().lower()
    if choice in ("hardware", "hw", "h"):
        print("HARDWARE — fysisk authenticator via CTAP2/HID. Rör vid enheten vid prompt.")
        return True
    return False


def _flow_fido2_register() -> None:
    user = input("Användar-ID (t.ex. admin-01): ").strip()
    hardware = _pick_backend()
    if not hardware:
        print("Registrering sker i mock-läge (SIMULATED / TEST-ONLY).")
    require_uv = confirm("Kräv PIN/biometri (user verification)")
    if not confirm("Fortsätt med registrering för %s" % user):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    report(fido2_cmd.run_register(user, yes=True, hardware=hardware,
                                  require_uv=require_uv))


def _flow_fido2_authenticate() -> None:
    user = input("Användar-ID: ").strip()
    credential = input("Credential-ID (tomt = aktiv credential): ").strip() or None
    hardware = _pick_backend()
    require_uv = confirm("Kräv PIN/biometri för detta beslut")
    report(fido2_cmd.run_authenticate(user, credential=credential, hardware=hardware,
                                      require_uv=require_uv))


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
    if not confirm("Fortsätt med spärrning"):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    report(fido2_cmd.run_credential_revoke(credential, yes=True))


def _flow_fido2_set_policy() -> None:
    credential = input("Credential-ID: ").strip()
    if not credential:
        print("Inget credential angivet. Tillbaka i huvudmenyn.")
        return
    policy = _pick("Ny UV-policy:", list(fido2.UV_POLICIES))
    if policy is None:
        return
    if not confirm("Fortsätt med policyändring till %s" % policy):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    report(fido2_cmd.run_credential_set_policy(credential, policy, yes=True))


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
    print("Monitor öppnar %s för läsning. Skriver aldrig till enheten; "
          "kan inte styra den." % port)
    if not confirm("Fortsätt med skrivskyddad läsning av %s" % port):
        print("Avbrutet av användaren. Tillbaka i huvudmenyn.")
        return
    report(monitor_cmd.run(device, port))


def handle_choice(choice: str) -> bool:
    """Utför ett menyval. Returnerar True om TUI:t ska avslutas."""
    if registry.dispatch_tui(choice):
        return False
    if choice == "1":
        _flow_test_all()
    elif choice == "2":
        _flow_test_suite()
    elif choice == "4":
        _flow_encode()
    elif choice == "5":
        _flow_decode()
    elif choice == "7":
        _flow_build()
    elif choice == "8":
        report(device_cmd.run_list())
    elif choice == "9":
        _flow_monitor()
    elif choice == "10":
        _flow_mamabear()
    elif choice == "11":
        _flow_fido2_register()
    elif choice == "12":
        _flow_fido2_authenticate()
    elif choice == "13":
        report(fido2_cmd.run_credential_list())
    elif choice == "14":
        _flow_fido2_revoke()
    elif choice == "15":
        _flow_fido2_simulate()
    elif choice == "16":
        report(fido2_cmd.run_audit())
    elif choice == "17":
        report(fido2_cmd.run_device_list())
    elif choice == "18":
        _flow_fido2_export()
    elif choice == "19":
        _flow_fido2_set_policy()
    elif choice == "0":
        print("Avslutar.")
        return True
    else:
        print("Ogiltigt val: %r. Välj 0–19." % choice)
    return False


def run() -> int:
    """Huvudloop. 0 = normalt avslut; Ctrl-C vid menyn avslutar också rent."""
    print(HEADER)
    print("Interaktivt läge. Styr eller verifierar ingen fysisk hårdvara.")
    while True:
        print()
        print(MENU)
        try:
            choice = input("Välj [0-19]: ").strip()
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
