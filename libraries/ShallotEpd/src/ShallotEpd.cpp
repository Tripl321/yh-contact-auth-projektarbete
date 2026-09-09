// SHALLOT — e-Paper Status Display Driver implementation.
// Panel config: Feather RP2350 SPI0, CS=5, DC=A0(26), RST=A1(27), BUSY=D25(25).
// Uses the GxEPD2 3-color driver so the red plane is always written white
// (the B/W driver leaves a persistent red background). Full refresh ~14 s;
// GxEPD2 uses timed waits (BUSY may not be wired).

#include <GxEPD2_3C.h>

#include "ShallotEpd.h"

GxEPD2_3C<GxEPD2_154_Z90c, GxEPD2_154_Z90c::HEIGHT> display(
  GxEPD2_154_Z90c(5, 26, 27, 25)  // CS, DC, RST, BUSY
);

static EpdStatus lastShownStatus = EPD_STATUS_BLANK;
static uint8_t hasShownResult = 0;
static uint8_t epdDegraded = 0;  // set when a refresh stalls; cleared by re-init

#if defined(ARDUINO_ARCH_RP2040)
// Feeds the RP2040/RP2350 hardware watchdog from inside GxEPD2 busy
// waits (called ~every ms while the panel is busy). A healthy ~14 s
// full refresh must never look like a lockup; a truly wedged panel
// still escapes via the library's own busy timeout, which the stall
// detector below then turns into a full re-init.
static void epdFeedWatchdog(const void*) {
  rp2040.wdt_reset();
}
#endif

static void epdHwInit(void) {
  display.init(0, true, 2, false);  // serial_diag, initial, reset_duration, pulldown_rst
  display.setRotation(0);
#if defined(ARDUINO_ARCH_RP2040)
  display.epd2.setBusyCallback(epdFeedWatchdog);
#endif
}

void epdInit(void) {
  epdHwInit();
  epdDegraded = 0;
}

static void epdResetGuards(void) {
  lastShownStatus = EPD_STATUS_BLANK;
  hasShownResult = 0;
}

static const char* epdStateName(EpdStatus status) {
  switch (status) {
    case EPD_STATUS_AUTHENTICATING: return "authenticating";
    case EPD_STATUS_AUTHENTICATED: return "authenticated";
    case EPD_STATUS_FAILED: return "failed";
    case EPD_STATUS_BLANK: return "blank";
  }
  return "unknown";
}

static void epdDrawStatus(EpdStatus status) {
  // Restore the screen buffer to full window (necessary after powerOff)
  display.setFullWindow();
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);

    int cx = 100, cy = 100, r = 50;

    display.drawRect(4, 4, 192, 192, GxEPD_BLACK);

    switch (status) {
      case EPD_STATUS_AUTHENTICATING:
        display.drawCircle(cx, cy, r, GxEPD_BLACK);
        display.fillCircle(cx, cy - r / 2, r / 5, GxEPD_BLACK);
        display.fillCircle(cx - r / 2, cy + r / 2, r / 5, GxEPD_BLACK);
        display.fillCircle(cx + r / 2, cy + r / 2, r / 5, GxEPD_BLACK);
        break;

      case EPD_STATUS_AUTHENTICATED: {
        display.drawCircle(cx, cy, r, GxEPD_BLACK);
        int s = r * 2 / 3;
        display.drawLine(cx - s, cy, cx - s / 4, cy + s / 2, GxEPD_BLACK);
        display.drawLine(cx - s / 4, cy + s / 2, cx + s, cy - s / 2, GxEPD_BLACK);
        break;
      }

      case EPD_STATUS_FAILED: {
        display.drawCircle(cx, cy, r, GxEPD_BLACK);
        int s = r * 2 / 3;
        display.drawLine(cx - s, cy - s, cx + s, cy + s, GxEPD_BLACK);
        display.drawLine(cx - s, cy + s, cx + s, cy - s, GxEPD_BLACK);
        break;
      }

      default:
        break;
    }
  } while (display.nextPage());
}

void epdShowStatus(EpdStatus status) {
  if (!epdShouldRefresh(status, lastShownStatus, hasShownResult)) {
    Serial.print("[PRO-57] show ");
    Serial.print(epdStateName(status));
    Serial.println(": suppressed (guard)");
    return;
  }
  if (epdDegraded) {
    // Safe recovery: a stalled panel gets a full re-init before the next
    // show instead of repeating into the wedge. Starts blank-guarded like boot.
    Serial.println("[PRO-57] Re-initializing wedged e-paper before show.");
    epdHwInit();
    epdDegraded = 0;
  }
  if (status == EPD_STATUS_AUTHENTICATED || status == EPD_STATUS_FAILED) {
    hasShownResult = 1;
  }
  lastShownStatus = status;
  Serial.print("[PRO-57] show ");
  Serial.print(epdStateName(status));
  Serial.println(": refresh");
  uint32_t drawStartMs = millis();
  epdDrawStatus(status);
  if (millis() - drawStartMs > EPD_STALL_MS) {
    // The library's busy timeout let go, but far too late: flag the panel
    // so the next show recovers via re-init. Never claims success falsely.
    Serial.println("[PRO-57] e-Paper refresh stalled; flagging for re-init.");
    epdDegraded = 1;
  }
}

void epdTestCycle(void) {
  static const uint32_t EPD_TEST_HOLD_MS = 1500;
  epdResetGuards();
  for (uint8_t i = 0; i < EPD_TEST_SEQUENCE_LEN; i++) {
    EpdStatus s = (EpdStatus)EPD_TEST_SEQUENCE[i];
    Serial.print("[PRO-57] Test mode: showing state ");
    Serial.println((int)s);
    epdShowStatus(s);
    delay(EPD_TEST_HOLD_MS);
  }
}

uint8_t epdPollTestRequest(uint32_t windowMs) {
  uint32_t start = millis();
  while ((int32_t)(millis() - start) < (int32_t)windowMs) {
    if (Serial.available()) {
      int c = Serial.peek();
      if (c == 't' || c == 'T' || c == 'w' || c == 'W') {
        Serial.read();  // consume only the test key
        return (uint8_t)c;
      }
      return 0;  // foreign byte: leave it for the protocol, no test mode
    }
    delay(10);
  }
  return 0;
}
