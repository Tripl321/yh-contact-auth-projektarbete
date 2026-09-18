"""PRO-97: separat, tidsbegränsat break-glass-flöde på DEN.

Fysisk USB-konsol + tvåpersons-ceremoni (ARM visar färsk ticket,
CONFIRM ekar den inom fönstret), audit-logg i SRAM, larm vid beviljande.
Aldrig permanent bypass: ordinarie auth-väg orörd, allt förfaller till
DENIED (timeout/fel/omstart), ingen flash.

Källguards verifierar inkopplingen; spegeln nedan verifierar ceremonin.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEN = (ROOT / "plc/den-main/den-main.ino").read_text(errors="replace")

ARM_WINDOW = int(re.search(r"#define BG_ARM_WINDOW_MS\s+(\d+)", DEN).group(1))
GRANT_WINDOW = int(re.search(r"#define BG_GRANT_WINDOW_MS\s+(\d+)", DEN).group(1))


def _den_on_response_body():
    lines = DEN.splitlines()
    start = next(i for i, l in enumerate(lines) if "den_on_response(" in l
                 and "static void" in l)
    depth, begun = 0, False
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            begun = True
        if begun and depth == 0:
            return "\n".join(lines[start:i + 1])
    raise AssertionError("unbalanced: den_on_response")


def test_pro97_windows_bounded():
    assert 0 < ARM_WINDOW <= 120000
    assert ARM_WINDOW <= GRANT_WINDOW <= 300000


def test_pro97_states_and_codes_exist():
    assert "DEN_ST_BG_ARMED" in DEN and "DEN_ST_BG_GRANTED" in DEN
    assert "DEN_REASON_BG_ARMED = 9" in DEN
    assert "DEN_REASON_BG_GRANTED = 10" in DEN
    assert "DEN_REASON_BG_DENIED = 11" in DEN


def test_pro97_ordinary_auth_path_untouched():
    body = _den_on_response_body()
    assert "BG_" not in body and "BREAKGLASS" not in body
    assert "DEN_ST_BG_" not in body


def test_pro97_no_input_echo():
    assert "Serial.print(bgLine" not in DEN
    assert "Serial.println(bgLine" not in DEN
    assert "Serial.write(bgLine" not in DEN


def test_pro97_boot_locked_and_audited():
    setup = DEN[DEN.find("void setup()"):]
    assert "bg_audit(BG_EV_BOOT)" in setup
    assert "BOOT locked (DENIED)" in setup


def test_pro97_audit_ring_is_sram_only():
    assert "bgAudit[BG_AUDIT_N]" in DEN
    assert "EEPROM" not in DEN and "LittleFS" not in DEN


class _BG:
    DENIED, ARMED, GRANTED = "DENIED", "ARMED", "GRANTED"

    def __init__(self, tickets):
        self.state = self.DENIED
        self.tickets = list(tickets)
        self.ticket = None
        self.t0 = 0
        self.audit = []

    def _relock(self, ev, now):
        self.ticket = None
        self.state = self.DENIED
        self.audit.append((ev, now))

    def input(self, line, now):
        if line == "BG ARM":
            if self.state != self.DENIED:
                return "IGNORED"
            if not self.tickets:
                self._relock("DENIED", now)
                return "DENIED"
            self.ticket = self.tickets.pop(0)
            self.state, self.t0 = self.ARMED, now
            self.audit.append(("ARMED", now))
            return "ARMED"
        if line.startswith("BG CONFIRM "):
            if self.state != self.ARMED or self.ticket is None:
                self._relock("DENIED", now)
                return "DENIED"
            if now - self.t0 >= ARM_WINDOW or line[11:] != self.ticket:
                self._relock("DENIED", now)
                return "DENIED"
            self.ticket = None
            self.state, self.t0 = self.GRANTED, now
            self.audit.append(("GRANTED", now))
            return "GRANTED"
        if line == "BG ABORT":
            if self.state in (self.ARMED, self.GRANTED):
                self._relock("ENDED", now)
                return "ABORTED"
            return "IGNORED"
        if line == "BG STATUS":
            if self.state in (self.ARMED, self.GRANTED):
                self.audit.append(("STATUS", now))
                return "STATUS"
            return "IGNORED"
        if self.state == self.ARMED:
            self._relock("DENIED", now)
            return "DENIED"
        if self.state == self.GRANTED:
            # Defined-actions-only: deny + audit, stay in bounding window.
            self.audit.append(("DENIED", now))
            return "CMD-DENIED"
        return "IGNORED"

    def poll(self, now):
        if self.state == self.ARMED and now - self.t0 >= ARM_WINDOW:
            self._relock("EXPIRED", now)
            return "EXPIRED"
        if self.state == self.GRANTED and now - self.t0 >= GRANT_WINDOW:
            self._relock("ENDED", now)
            return "ENDED"
        return self.state


def test_pro97_approved_flow():
    b = _BG(["A1B2C3D4"])
    assert b.input("BG ARM", 0) == "ARMED"
    assert b.input("BG CONFIRM A1B2C3D4", 1000) == "GRANTED"
    assert b.poll(1000 + GRANT_WINDOW - 1) == "GRANTED"
    assert [e for e, _ in b.audit] == ["ARMED", "GRANTED"]


def test_pro97_wrong_ticket_denies_and_relocks():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    assert b.input("BG CONFIRM 00000000", 1000) == "DENIED"
    assert b.state == _BG.DENIED
    assert b.input("BG CONFIRM A1B2C3D4", 2000) == "DENIED"  # ticket död


def test_pro97_expired_arm_denies():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    assert b.input("BG CONFIRM A1B2C3D4", ARM_WINDOW) == "DENIED"
    assert b.state == _BG.DENIED


def test_pro97_confirm_without_arm_denies():
    assert _BG(["A1B2C3D4"]).input("BG CONFIRM A1B2C3D4", 0) == "DENIED"


def test_pro97_arm_outside_idle_ignored():
    b = _BG(["T1", "T2"])
    b.input("BG ARM", 0)
    assert b.input("BG ARM", 1000) == "IGNORED"
    assert b.input("BG CONFIRM T1", 2000) == "GRANTED"


def test_pro97_grant_timeout_relocks():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    b.input("BG CONFIRM A1B2C3D4", 1000)
    assert b.poll(1000 + GRANT_WINDOW) == "ENDED"
    assert b.state == _BG.DENIED


def test_pro97_abort_relocks_early():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    assert b.input("BG ABORT", 1000) == "ABORTED"
    assert b.state == _BG.DENIED


def test_pro97_restart_is_locked():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    b.input("BG CONFIRM A1B2C3D4", 1000)
    b2 = _BG([])  # omstart: nytt SRAM-tillstånd
    assert b2.state == _BG.DENIED
    assert b2.input("BG CONFIRM A1B2C3D4", 2000) == "DENIED"


def test_pro97_rearm_replaces_ticket():
    b = _BG(["OLD", "NEW"])
    b.input("BG ARM", 0)
    assert b.poll(ARM_WINDOW) == "EXPIRED"
    assert b.input("BG ARM", ARM_WINDOW + 1) == "ARMED"  # ny ticket NEW
    assert b.input("BG CONFIRM OLD", ARM_WINDOW + 2) == "DENIED"  # OLD död
    c = _BG(["NEW"])
    c.input("BG ARM", 0)
    assert c.input("BG CONFIRM NEW", 1) == "GRANTED"


def test_pro97_malformed_input_relocks():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    assert b.input("BG CONFIRM SHORT", 1000) == "DENIED"
    assert b.state == _BG.DENIED


def test_pro97_granted_allows_defined_status():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    b.input("BG CONFIRM A1B2C3D4", 1000)
    assert b.input("BG STATUS", 2000) == "STATUS"
    assert b.state == _BG.GRANTED  # read-only: window unaffected
    assert ("STATUS", 2000) in b.audit  # every use traceable


def test_pro97_granted_denies_unknown_command_but_stays():
    b = _BG(["A1B2C3D4"])
    b.input("BG ARM", 0)
    b.input("BG CONFIRM A1B2C3D4", 1000)
    assert b.input("BG REBOOT", 2000) == "CMD-DENIED"
    assert b.state == _BG.GRANTED  # window still bounds everything
    assert ("DENIED", 2000) in b.audit
    assert b.poll(1000 + GRANT_WINDOW) == "ENDED"  # window still relocks


def test_pro97_status_outside_service_ignored():
    assert _BG(["A1B2C3D4"]).input("BG STATUS", 0) == "IGNORED"


def test_pro97_scope_banner_and_allow_list():
    assert "Defined actions only: BG STATUS, BG ABORT" in DEN
    assert "NOT an emergency stop" in DEN
    assert "BG_EV_STATUS" in DEN
    assert "static void bg_status(void)" in DEN
