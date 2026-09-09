/*
 * SHALLOT — e-Paper Refresh Policy (hardware-independent)
 *
 * Pure decision logic for the PAW status display, kept free of Arduino
 * and GxEPD2 dependencies so it can be verified on host. The driver
 * (ShallotEpd.h) applies these rules before touching the panel.
 *
 * Status modes:
 *   AUTHENTICATING — challenge in progress (dots icon)
 *   AUTHENTICATED  — approved (checkmark icon)
 *   FAILED         — denied (cross icon)
 *   BLANK          — empty screen (frame only)
 *
 * Refresh limits (a 3-color full refresh flickers and blocks ~14 s):
 *   - never redraw the already-shown status
 *   - once a definitive result (approved/denied) is shown, suppress
 *     further AUTHENTICATING splashes (no bounce on timeouts/retries)
 */

#ifndef SHALLOT_EPD_POLICY_H
#define SHALLOT_EPD_POLICY_H

#include <stdint.h>

typedef enum {
  EPD_STATUS_AUTHENTICATING = 0,
  EPD_STATUS_AUTHENTICATED = 1,
  EPD_STATUS_FAILED = 2,
  EPD_STATUS_BLANK = 3
} EpdStatus;

// Returns 1 when showing `next` requires a panel refresh given the
// currently shown status and whether a definitive result was shown.
static inline uint8_t epdShouldRefresh(EpdStatus next, EpdStatus shown, uint8_t hasResult) {
  if (next == shown) return 0;
  if (next == EPD_STATUS_AUTHENTICATING && hasResult) return 0;
  return 1;
}

// Display test-mode order: every status exactly once, ending blank.
#define EPD_TEST_SEQUENCE_LEN 4
static const uint8_t EPD_TEST_SEQUENCE[EPD_TEST_SEQUENCE_LEN] = {
  (uint8_t)EPD_STATUS_AUTHENTICATING,
  (uint8_t)EPD_STATUS_AUTHENTICATED,
  (uint8_t)EPD_STATUS_FAILED,
  (uint8_t)EPD_STATUS_BLANK
};

#endif  // SHALLOT_EPD_POLICY_H
