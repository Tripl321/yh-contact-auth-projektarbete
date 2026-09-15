"""`shallot verify flow` — reproducerbart 4-stegs testflöde (TEST-ONLY)."""

from __future__ import annotations

import json
import sys

from shallot_cli import flow


def run(scenario: str, as_json: bool = False) -> int:
    """Kör ett scenario eller alla. Exit 0 = förväntat utfall i alla steg,
    1 = oväntat utfall (motorfel), 2 = felaktig användning."""
    names = list(flow.SCENARIOS) if scenario == "all" else [scenario]
    if scenario != "all" and scenario not in flow.SCENARIOS:
        print("error: okänt flöde %r (välj: %s)" % (scenario, "|".join(list(flow.SCENARIOS) + ["all"])),
              file=sys.stderr)
        return 2
    try:
        results = [flow.run_flow(n) for n in names]
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    ok = all(r["matches_expected"] for r in results)
    if as_json:
        print(json.dumps(results if scenario == "all" else results[0], indent=2))
    elif scenario == "all":
        for r in results:
            print("%-10s : %s (kod %s: %s) e-paper=%s" % (
                r["scenario"], r["result"], r["reason_code"], r["reason"],
                r["epaper"]["status"]))
        print("flöden: %d/%d med förväntat utfall" % (
            sum(1 for r in results if r["matches_expected"]), len(results)))
    else:
        print(flow.render(results[0]))
    return 0 if ok else 1
