"""Edge- och arkivresponsernas utvecklingsnyckel: TEST-ONLY + fail-closed opt-in.

plc/edge-challenge-response/edge-challenge-response.ino bäddar in den
publika bänkvektorn MASTER_KEY = 00..0F. Den får aldrig kompileras tyst
till en firmware-artefakt: bygget kräver explicit -DEDGE_ALLOW_DEV_KEY=1
(bänk/CI) och vägrar annars med #error.

id-kort/archive/.../paw-challenge-response.ino bar samma vektor helt
oskyddad. Den är nu guardad på motsvarande sätt
(-DPAW_ARCHIVE_ALLOW_DEV_KEY=1), så att ingen kan bygga en artefakt av den
arkiverade filen ens av misstag. Testerna nedan låser båda beteendena.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
EDGE = ROOT / "plc/edge-challenge-response/edge-challenge-response.ino"
ARCHIVE = (
    ROOT
    / "id-kort/archive/paw-challenge-response-responder/paw-challenge-response.ino"
)


def _src():
    return EDGE.read_text(errors="replace")


def _archive_src():
    return ARCHIVE.read_text(errors="replace")


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


# ---------------------------------------------------------------------------
# Arkiverad PAW-responder: samma vektor, fail-closed guard (PRO-93-mönster)
# ---------------------------------------------------------------------------


def test_archived_dev_vector_is_marked_test_only():
    src = _archive_src()
    assert "TEST-ONLY" in src
    assert "MASTER_KEY" in src  # känd bänkvektor, dokumenterad — inte dold
    assert "ARKIVERAD" in src


def test_archived_build_is_fail_closed_without_opt_in():
    """Guardet måste vara verkliga preprocessordirektiv vid radstart, precis
    som för edge-skissen: annars kan en arkiverad fil byggas av misstag."""
    src = _archive_src()
    assert re.search(r"^\s*#\s*ifndef\s+PAW_ARCHIVE_ALLOW_DEV_KEY\b", src, re.M)
    assert re.search(r"^\s*#\s*error\b", src, re.M)
    assert re.search(r"^\s*#\s*endif\b", src, re.M)


def test_archived_guard_aborts_before_the_key():
    """Utan opt-in-flaggan måste preprocessorn avbrytas FÖRE nyckeln.

    #ifndef/#error/#endif ligger alltså före MASTER_KEY-deklarationen
    (samma form som edge-skissen). Nyckeln får inte ligga i en #else-gren
    eller på annat sätt kunna komma med i en artefakt utan flaggan.
    Matcha radstart-preprocessordirektiv, inte kommentarräknande omnämnanden."""
    lines = _archive_src().splitlines()

    def first(pattern):
        return next(
            i for i, l in enumerate(lines) if re.match(pattern, l)
        )

    guard = first(r"^\s*#\s*ifndef\s+PAW_ARCHIVE_ALLOW_DEV_KEY\b")
    error = next(
        i for i, l in enumerate(lines[guard:], start=guard)
        if re.match(r"^\s*#\s*error\b", l)
    )
    endif = next(
        i for i, l in enumerate(lines[guard:], start=guard)
        if re.match(r"^\s*#\s*endif\b", l)
    )
    key = first(r"^\s*static const uint8_t MASTER_KEY\[SHALLOT_MASTER_KEY_LEN\]")

    assert guard < error < endif < key
    assert not re.search(r"^\s*#\s*else\b", "\n".join(lines[guard:key]), re.M)


def test_archived_dev_key_is_never_opted_in_by_ci():
    """Ingen workflow får bygga den arkiverade filen."""
    opt_in = "-DPAW_ARCHIVE_ALLOW_DEV_KEY=1"
    for wf in sorted((ROOT / ".github/workflows").glob("*.yml")):
        assert opt_in not in wf.read_text(), wf.name
