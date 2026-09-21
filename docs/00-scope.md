# 00 — Project Scope (post-pivot)

**Status:** Aktiv 2026-09-09 | Ersätter tidigare LoRa-felsökning som spår.

## Prioritetsordning

1. **Upprätthåll verifierad DEN↔PAW UART-dockautentisering.**
    Logik, felvägar och kryptovektorer är testlåsta i pytest (551 tests);
    2 s-deadline, konstanttidsjämförelse, K_mac-användning och
    responder-only-beteende är frozen i källguards. Fysisk bänkacceptans
    enligt `docs/13-pro-53-fail-closed` (§3) — sammansatt DEN+PAW E2E återstår.
    **Transporten är UART (Serial1) — LoRa är explicit ur scope.**
2. **Slutför Mama Bear USB-C-nyckelprovisionering** när sändarsidan är klar
   (issue #9). PAW lyssnar redan på USB Serial; ingen provisionering över
   Serial1 (GPIO0/1 tillhör exklusivt DEN-dockan).
3. **E-paper är ett fristående hårdvaru/UI-spår.** Det måste förbli
   icke-blockerande och får aldrig fördröja dock-autentisering
   (request + background-poll med degraded-läge, se PR #13).

## Regler

- LoRa-radiofelsökning är **explicit ur scope** tills en framtida uppgift
  riktar TX-only-larmkanalen. Utred, reparera, initiera eller testa inte
  SX1262/LoRa i UART-, provisionerings- eller e-paper-uppgifter.
- Ett LoRa `-2`-initieringsfel är icke-blockerande och loggas **högst en
  gång** (redan uppfyllt: `paw-main.ino` loggar endast i `setup()`).
- Rapporter hålls till det aktiva spåret; LoRa listas endast när det
  direkt blockerar ett bygge.
- Fysisk bänkpraxis från integrationen: verifiera varje flash med
  bootkontroll, mellanlagra UF2:er utanför `/tmp` (städas aggressivt).

## Referenser

- Pivotbeslut: `docs/architecture-pivot-2026-09-09.md`
- Dock-protokoll: `docs/11-dockat-uart-protokoll.md`
- Fail-closed & bänkacceptans: `docs/13-pro-53-fail-closed.md`
- Integration & bevisstatus: `docs/09-integrationsbeskrivning.md`
- Öppna spår: issue #9 (Mama Bear USB-sändare), PR #13 (responsiv dockning)
