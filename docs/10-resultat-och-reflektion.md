# 10 — Resultat och reflektion (PRO-68)

**Status:** Utkast 2026-09-18 | PRO-68 | Sammanfattar verifierade resultat.
Trevägsmarkering genomgående: **[K]** kod/test-verifierat i suite,
**[B]** fysiskt bänkverifierat enligt projektets bänkdokumentation,
**[R]** restrisk/öppet. Inga produktions- eller compliancepåståenden.

## Verifierade resultat [K]

- **Fail-closed sessioner:** PAW nekar utan giltig nyckel (även all-zero
  master), DEN nekar alla felvägar via `den_fail` → DENIED + nonce-wipe,
  beviljande kräver komplett giltigt RESPONSE inom 2 s
  (`test_pro84/88/53`, `test_pro61/62`).
- **SRAM-rensning:** nycklar endast i SRAM, wipe vid boot/timeout/fel/ny
  session; inga persistenta lagrings-API:er; känsliga loggar bakom
  `SECURE_DEBUG` (PRO-94, 30 guardtester).
- **Kortlivade sessioner:** DEN återgår till DENIED efter sessionsgap;
  PAW beviljandevisning förfaller efter 30 s oavsett tillstånd; omstart
  = låst + nyckeltork (PRO-95, 11 tester).
- **Break-glass-avgränsning:** separat tillstånd, ticket-ceremoni,
  60 s/120 s-fönster, auto-relock, definierade åtgärder STATUS/ABORT,
  audit + larm; ordinarie auth-väg orörd (PRO-97, 20 tester).
- **Hotmodell och integration:** PRO-55 (tillgångar, 7 gränser, 12
  restrisker) och PRO-67 (statusmatris [I]/[B]/[R]) dokumenterade utan
  verktygsgenererade påståenden.
- **Hygien:** inga hårdkodade dev-nycklar i aktiv firmware (PRO-93 +
  doctor-guard + CI); simulerings- och demoflöden märkta och hemlighets-
  fria (testlåst); FIDO2-maskning testlåst.

## Fysisk bänkverifiering [B]

Enligt `docs/13-pro-53-fail-closed`: 2 s-deadline och happy path är
acceptansbevisade på bänk (§3); återstår sammansatt E2E: K1–K6
(SRAM-volatilitet, UF2-inspektion, assembler-wipe, nollnyckel-nekande,
timeout-clear, trådanalys), break-glass-ceremoni på enhet, panelbeteende
samt pen-testfallen i PRO-63-underlaget — all bänkevidens loggas per
fall, inga hårdvarupåståenden utan loggutdrag.

## Restrisker [R]

Se PRO-55 punkterna 1–12 (fysisk possession, ceremoni utan sändarauth,
HSM-flöde, flyktig audit, single-operator, oberoende audit, sidokanaler,
e-paper-frys, ECC, K1–K6, supply chain, duress). Tillkommer: secure
element saknas (PRO-54); nyckelrotation saknas; sequential IV-återställs
vid omstart (se docs/07).

## Reflektion

Arkitekturens bärande beslut — SRAM-only nycklar, fail-closed som
default, kortlivade tillstånd, separata flöden för service — har hållit
genom granskningarna PRO-93–PRO-97: varje fynd kunde åtgärdas lokalt
utan protokolländring. Dyraste lärdomen: visnings- och indikeringstill-
stånd (e-paper, larm) behöver samma livscykelgranskning som
kryptotillstånd — stillastående bilder ljuger tyst. Nästa steg med störst
riskreduktion per krona: sammansatt bänk (K1–K6 + PRO-63) före all
hårdvarulåsning, därefter oberoende kryptoaudit, därefter secure element.

## Kända testbegränsningar (accepterade 2026-09-19)

- **Ordningsberoende flake:** `test_fido2_cmd` har gett två spontana
  felslag i full suite (endast vid kombinerad körning; passerar alltid
  isolerat, i fil och vid omkörning). 0/65+ reproduktionsförsök med
  stresslast, halvor och fångstloop — grundorsaken obevisad. Accepterat:
  hermetisk autouse-fixture (`SHALLOT_FIDO2_STORE` → tmp) sitter som
  defense-in-depth, och suiten har visat 542/0 vid flera tillfällen.
  Återkommer felen med full traceback utlöser ny granskning.
- **test_pro45-driften** (STM32-register vs Zephyr-design) — löst:
  testerna låser beslutad design (wayfinder-biljett 03, PR #45).
