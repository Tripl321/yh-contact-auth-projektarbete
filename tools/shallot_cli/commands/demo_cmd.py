"""`shallot demo incident` — simulerad säkerhetsincident för presentation."""

from __future__ import annotations

from shallot_cli import incident


def run() -> int:
    print(incident.render(incident.run_incident()))
    return 0
