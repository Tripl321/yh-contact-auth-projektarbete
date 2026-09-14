"""`shallot device list` — skrivfri uppräkning av serieportar."""

from __future__ import annotations

from shallot_cli import serial_adapters


def run_list() -> int:
    ports = serial_adapters.list_ports()
    if not ports:
        print("Inga serieportar hittades.")
        return 0
    print("%-18s %-28s %s" % ("PORT", "BESKRIVNING", "HWID"))
    for p in ports:
        print("%-18s %-28s %s" % (p["device"], p["description"][:28], p["hwid"]))
    print("Identifiering osäker (gissning utifrån namn/Vid:Pid) — ingen skrivning utförd.")
    return 0
