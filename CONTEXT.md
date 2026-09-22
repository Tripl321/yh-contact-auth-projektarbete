# CONTEXT.md — domänglossar + beslutade fördjupningar (tools/shallot_cli)

## Domäntermer (från docs/)

- **PAW** — brickan (ID-kortet) som autentiserar sig.
- **DEN** — dockan/låset som fattar det lokala fail-closed-beslutet.
- **MamaBear** — nyckelsmeden: skapar och delar ut nycklar via USB.
- **Credential** — FIDO2-meriten (skapad-tid, status, policy + publik HW-nyckel).
- **Ceremony** — challenge-livscykel (singelbruk + timeout) för en session.
- **Allowlist** — enda tillåtna kommandon/vägar; allt annat nekas fail-closed.
- **Installationskod** — sexsiffrig Admin-kod; endast saltad hash lagras (OS-lagret).
- **Admin-session** — 15 min glidande inaktivitetstid efter FIDO2 + kod.
- **Valv** — OS-säker lagring för kodhashen (Keychain/secret-tool, fail-closed).
- **Fysisk återställning** — enda sättet att skapa ny kod (färsk HW-assertion + --confirm).
- **Sändare** — CLI-sändning av fast testnyckel över USB (HANDSHAKE → READY → KEY_DATA → STORED).
- **Demoläge** — TUI-flöde Meny → DEMO → Starta demo: tester, sedan fysisk bänk med verdict från logg + display.

## Beslutade fördjupningar (grillade 2026-09-22, alla åtta)

1. **Output-regel** — enas i `mamabear.py`; `fido2_cmd` importerar därifrån.
2. **ConfirmGateway** — commands tar injicerbar confirm-funktion; TUI + test-fake är adaptrar.
3. **Verifier** — ny modul för hela ALLOW/DENY-beslutet; Ceremony krymper till challenge-lager direkt. (Bevaka importcykel verifier↔fido2.)
4. **Backend-capabilities** — full uppdelning: RpVerifier + Signer (mock) + CtapCeremony; `sign`/`verify` bort från HW.
5. **Credential-post** — bor i `fido2.py`, tunna wrappers i store; första snittet: validering + builders (fingerprint/export flyttas senare).
6. **Store** — internt objekt, publikt funktions-API oförändrat.
7. **Command** — äger arguments/run/tui-flöde som callables; tunna `*_cmd`-shims löses upp.
8. **ScenarioHarness** — en parameteriserad harness för sim + fido2; `mamabear.sanitize`-aliaset bort.

## Byggordning (beroenden först)

5 → 3 → 4 → 6 → 1 → 2 → 7 → 8.
