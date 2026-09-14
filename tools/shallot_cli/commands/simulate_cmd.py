"""`shallot simulate auth` — deterministisk DEN–PAW-simulering."""

from __future__ import annotations

import sys

from shallot_cli import sim


def run(scenario: str) -> int:
    try:
        res = sim.run_scenario(scenario)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print(sim.render(res))
    return 0
