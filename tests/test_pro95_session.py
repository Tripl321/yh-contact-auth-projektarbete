"""PRO-95: begränsad PAW-behörighet och sessionsgiltighet.

Åtkomst gäller endast under ett tydligt, kortlivat, verifierbart tillstånd:
- Beviljande-visningen (e-paper AUTHENTICATED) förfaller efter
  AUTH_GRANTED_DISPLAY_MS och återgår till låst läge (AUTHENTICATING).
- Sessionen upphör vid timeout/fel/omstart/ogiltigt resultat; protokollet
  återgår till WAITING_FOR_CHALLENGE (PAW) / DENIED (DEN).
- Omstart = låst: setup() visar AUTHENTICATING, aldrig AUTHENTICATED.

Källguards verifierar inkopplingen; spegeln nedan verifierar regeln.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAW = (ROOT / "id-kort/paw-main/paw-main.ino").read_text(errors="replace")
DEN = (ROOT / "plc/den-main/den-main.ino").read_text(errors="replace")

WINDOW = int(re.search(r"#define AUTH_GRANTED_DISPLAY_MS\s+(\d+)", PAW).group(1))


def test_pro95_window_is_defined_and_short_lived():
    assert 0 < WINDOW <= 60000


def test_pro95_grant_arms_display_window_on_both_paths():
    assert PAW.count("authDisplayed = true") == 2  # dock-ACK + LoRa-RESULT
    assert PAW.count("authGrantedAt = millis()") == 2


def test_pro95_expiry_reverts_to_locked():
    assert "authDisplayed = false" in PAW
    assert "epd.showStatus(EPD_STATUS_AUTHENTICATING)" in PAW


def test_pro95_boot_is_locked():
    setup = PAW[PAW.find("void setup()"):]
    setup = setup[: setup.find("\n}\n")]
    assert "EPD_STATUS_AUTHENTICATING" in setup
    assert "EPD_STATUS_AUTHENTICATED" not in setup
    assert "secure_clear_key()" in setup


def test_pro95_den_grant_returns_to_denied():
    assert "DEN_ST_AUTHENTICATED" in DEN
    assert "denState = DEN_ST_DENIED" in DEN


def test_pro95_invalid_result_denies():
    assert "EPD_STATUS_FAILED" in PAW  # ACK 0x00 / RESULT != 0x01 / ACK-timeout


class _GrantDisplay:
    """Spegel av PAW:s visningsfönster: grant() tänder, poll() släcker."""

    def __init__(self):
        self.shown_at = None

    def grant(self, now):
        self.shown_at = now

    def poll(self, now):
        if self.shown_at is not None and now - self.shown_at > WINDOW:
            self.shown_at = None
            return "AUTHENTICATING"
        return "AUTHENTICATED" if self.shown_at is not None else "AUTHENTICATING"


def test_pro95_valid_access_shows_grant_inside_window():
    d = _GrantDisplay()
    d.grant(1000)
    assert d.poll(1000) == "AUTHENTICATED"
    assert d.poll(1000 + WINDOW) == "AUTHENTICATED"  # gräns: > gäller
    assert d.poll(1000 + WINDOW + 1) == "AUTHENTICATING"


def test_pro95_expired_session_returns_to_locked():
    d = _GrantDisplay()
    d.grant(0)
    assert d.poll(WINDOW + 1) == "AUTHENTICATING"
    assert d.poll(10 * WINDOW) == "AUTHENTICATING"  # förblir låst


def test_pro95_regrant_rearms_window():
    d = _GrantDisplay()
    d.grant(0)
    d.grant(WINDOW)  # ny beviljad session innan förfall
    assert d.poll(2 * WINDOW) == "AUTHENTICATED"
    assert d.poll(2 * WINDOW + 1) == "AUTHENTICATING"


def test_pro95_never_granted_stays_locked():
    assert _GrantDisplay().poll(999999) == "AUTHENTICATING"
