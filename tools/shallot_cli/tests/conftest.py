"""Hermetisk testmiljö för tools-sviten (defense-in-depth).

Pekar SHALLOT_FIDO2_STORE på ett tmp-träd för varje test så att inget
test någonsin kan läsa/skriva den riktiga lagringen under $HOME —
oavsett ordning, parallellitet eller framtida test som glömmer
`isolated`-fixturen.
"""

import pytest

from shallot_cli import bench, demo
from shallot_cli.fido2_store import STORE_ENV


@pytest.fixture(autouse=True)
def _hermetic_store(tmp_path, monkeypatch):
    monkeypatch.setenv(STORE_ENV, str(tmp_path / "fido2-store"))
    monkeypatch.setenv(demo.DEMO_LOG_ENV, str(tmp_path / "demo-result.jsonl"))
    monkeypatch.setenv(demo.DEMO_SUMMARY_ENV, str(tmp_path / "demo-summary.txt"))
    monkeypatch.setenv(bench.BENCH_LOG_ENV, str(tmp_path / "bench-verify.jsonl"))
    monkeypatch.setenv(bench.BENCH_SUMMARY_ENV,
                       str(tmp_path / "bench-verify-summary.txt"))
