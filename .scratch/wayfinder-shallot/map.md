# Karta: SHALLOT — verifiera att allt är på plats

## Destination

Låst, verifierad väg till presentation 25 sep + slutinlämning 27 sep:
allt mergat i rätt ordning, bänken avgränsad och körd, suiten avgjord,
dokumentationen sann. Kartan är klar när inget återstår att besluta
innan utförandet — inte när allt är utfört.

## Notes

Domän: SHALLOT-glossary i docs/ (PAW/DEN/UNO-Q, fail-closed, K1–K6).
Sessions: grilling vid beslut; fakta hämtas ur kod/test/PR:er, aldrig
antas. Grundregel från beställaren: verifiera att saker ÄR på plats —
"verkar så" räcker inte. Svenska.

## Decisions so far

- [Karta täcker allt](tickets/00-destination.md) — kod, docs, bänk, presentation, inlämning; syfte verifiera, inte bygga nytt.
- [Horisont 25 + 27 sep](tickets/00-destination.md) — kartans bortre gräns.
- [Bänken ingår](tickets/00-destination.md) — dimmigaste området kartläggs igenom, inte runt.
- [Mergeordning docs-först](tickets/02-merge-docs.md) — #40→#41→#42→#44 mergade; #44 trots UNSTABLE (enbart basens kända fel).
- [Stäng #25 + #29](tickets/01-close-stale-prs.md) — #25 ersatt av 08:an, #29 vilande/driftad, båda stängda med kommentar.
- [Manuella PRO-55 räcker](tickets/00-destination.md) — LTM vilande (wizard + config klara).
- [test_pro45: testerna viker sig](tickets/03-pro45-yield.md) — Zephyr-design låst i tester, PR #45 mergad, suite 538/0 grön.
- [Full bänk före presentationen](tickets/04-bench-scope.md) — K1–K6 + ceremoni + panel, alla med evidens; #43 mergad, grindar över tagna.
- [#43 mergad](tickets/05-pr43-fate.md) — beslut onödigt; UNSTABLE var basens kända fel, åtgärdat i #45 före merge.

## Not yet specified

<!-- se "Fog of war": dimman är nu biljettad — inget kvar ospecificerat -->

## Out of scope

- Pen-tester (PRO-63-fallen) — strukna av beställaren; återkommer endast som färsk effort efter inlämning.
- LTM-verktygskörning — vilande beslut (manuella räcker); revival efter inlämning är ny effort.
- LoRa-aktivering, produktionshärdning, certifiering — bortom horisonten.
