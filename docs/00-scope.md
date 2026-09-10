# 00 — Project Scope (post-pivot)

**Status:** Aktiv 2026-09-09 | Ersätter tidigare LoRa-felsökning som spår.

## Prioritetsordning

1. **Upprätthåll verifierad DEN↔PAW UART-dockautentisering.**
   Happy path + fail-closed-negativtester är hårdvarubevisade (se
   `docs/12-dock-uart-integration.md`). Ändringar här får aldrig bryta
   2 s-deadline, konstanttidsjämförelse, K_mac-användning eller
   responder-only-beteende.
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
- Integration: `docs/12-dock-uart-integration.md`
- Öppna spår: issue #9 (Mama Bear USB-sändare), PR #13 (responsiv dockning)
