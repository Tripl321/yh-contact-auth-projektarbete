"""Interaktivt TUI-läge för `shallot` (startas utan argument).

TUI:t är ett tunt skal över befintliga kommandoimplementationer i
``shallot_cli.commands`` — ingen logik dupliceras här. All
hårdvarunära påverkan kräver bekräftelse (i praktiken: `monitor`,
som öppnar en serieport; allt annat är hårdvarufritt). Simuleringar
märks alltid SIMULATED / TEST-ONLY (via ``sim.render``).
"""

from __future__ import annotations

import sys

from shallot_cli import explain, fido2, registry, serial_adapters, sim, uart
from shallot_cli.commands import (
    build_cmd,
    demo_cmd,
    device_cmd,
    doctor_cmd,
    explain_cmd,
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

def _menu_max() -> int:
    """Högsta menynummer — genereras från registryt."""
    return max(n for n, _label in registry.menu_entries())


def _menu_text() -> str:
    lines = [" %d  %s" % (n, label) for n, label in registry.menu_entries()]
    lines.append(" 0  Avsluta")
    return "\n".join(lines)


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


def _flow_doctor() -> None:
    report(doctor_cmd.run())


def _flow_demo() -> None:
    print("Simulerad incident — SIMULERING.")
    report(demo_cmd.run())


def _flow_explain() -> None:
    topic = _pick("Ämnen:", explain.topic_names())
    if topic is None:
        return
    use_ai = confirm("Utveckla med lokal Ollama-modell")
    report(explain_cmd.run(topic, ai=use_ai))


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
    if choice == "0":
        print("Avslutar.")
        return True
    if registry.dispatch_tui(choice):
        return False
    print("Ogiltigt val: %r. Välj 0–%d." % (choice, _menu_max()))
    return False


def run() -> int:
    """Huvudloop. 0 = normalt avslut; Ctrl-C vid menyn avslutar också rent."""
    print(HEADER)
    print("Interaktivt läge. Styr eller verifierar ingen fysisk hårdvara.")
    while True:
        print()
        print(_menu_text())
        try:
            choice = input("Välj [0-%d]: " % _menu_max()).strip()
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
