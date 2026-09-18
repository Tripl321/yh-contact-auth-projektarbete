"""Edge-responserns utvecklingsnyckel: TEST-ONLY + fail-closed opt-in.

plc/edge-challenge-response/edge-challenge-response.ino bäddar in den
publika bänkvektorn MASTER_KEY = 00..0F. Den får aldrig kompileras tyst
till en firmware-artefakt: bygget kräver explicit -DEDGE_ALLOW_DEV_KEY=1
(bänk/CI) och vägrar annars med #error. Testerna nedan låser det beteendet.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
EDGE = ROOT / "plc/edge-challenge-response/edge-challenge-response.ino"


def _src():
    return EDGE.read_text(errors="replace")


def test_edge_dev_vector_is_marked_test_only():
    src = _src()
    assert "TEST-ONLY" in src
    assert "MASTER_KEY" in src  # känd bänkvektor, dokumenterad — inte dold


def test_edge_build_is_fail_closed_without_opt_in():
    """Guardet måste vara verkliga preprocessordirektiv vid radstart
    (inte omnämnanden i kommentarer): #ifndef ... #error ... #endif."""
    src = _src()
    assert re.search(r"^\s*#\s*ifndef\s+EDGE_ALLOW_DEV_KEY\b", src, re.M)
    assert re.search(r"^\s*#\s*error\b", src, re.M)
    assert re.search(r"^\s*#\s*endif\b", src, re.M)


def test_edge_opt_in_flag_name_is_stable():
    """CI och doctor refererar samma flaggnamn — bryt inte utan att
    uppdatera workflow + doctor_cmd samtidigt."""
    src = _src()
    assert src.count("EDGE_ALLOW_DEV_KEY") >= 3
    wf = (ROOT / ".github/workflows/build-paw-uf2.yml").read_text()
    assert "-DEDGE_ALLOW_DEV_KEY=1" in wf
