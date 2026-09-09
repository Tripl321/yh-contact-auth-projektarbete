/*
 * SHALLOT — e-Paper Status Display Driver (PAW)
 *
 * Owns the Waveshare 1.54" 3-color panel (GDEH0154Z90, SSD1682, 200x200)
 * behind a tiny status API so PAW logic never touches GxEPD2 directly:
 *
 *   epdInit()              — init panel, rotation 0
 *   epdShowStatus(s)       — guarded refresh per EpdPolicy.h
 *   epdTestCycle()         — test mode: every status once, ends blank
 *   epdPollTestRequest(ms) — 1 when the operator pressed t/T in window
 *
 * Privacy: icons only, never text or identity data.
 * Include with: #include <ShallotEpd.h>
 * Requires the GxEPD2 library on the build search path.
 */

#ifndef SHALLOT_EPD_H
#define SHALLOT_EPD_H

#include <Arduino.h>

#include "EpdPolicy.h"

// Stall bound: a healthy full refresh finishes well within the panel's
// 20 s busy timeout. Past this, the panel is treated as wedged and is
// fully re-initialized before the next show (safe recovery).
#define EPD_STALL_MS 30000

void epdInit(void);
void epdShowStatus(EpdStatus status);
void epdTestCycle(void);
// Test-mode poll: returns the pressed key ('t' display test, 'w' watchdog
// self-test), consumed, or 0 on timeout. A foreign byte is left unread
// for the protocol and also yields 0 (no test mode).
uint8_t epdPollTestRequest(uint32_t windowMs);

#endif  // SHALLOT_EPD_H
