# AGENTS.md — Instruktioner för kodagenter och utvecklare

Detta dokument definierar bindande krav för all kod, test och driftsättning i SHALLOT-projektets repo. Kodagenter (AI-assistenter) och mänskliga utvecklare ska följa dessa krav utan undantag om inte uttryckligen godkänts och dokumenterats.

## Obligatoriskt krav: LoRa duty cycle och radiosäker drift

Följande krav är bindande för alla implementationer, tester och driftsättningar som innefattar LoRa P2P-sändning i detta repo.

1. För LoRa P2P på 868,1 MHz ska implementationen utgå från högst 1 % duty cycle om LBT inte uttryckligen har implementerats och verifierats.
2. Sändbudgeten är högst 36 sekunders sammanlagd time-on-air per rullande 60 minuter.
3. All time-on-air ska räknas före sändning och bokföras per radio/subband.
4. Retries, ACK, challenge-response, felmeddelanden och heartbeat räknas alltid mot samma budget.
5. När budgeten är slut får systemet inte sända; paket ska köas, fördröjas eller undertryckas enligt prioritet.
6. Tester måste logga och redovisa time-on-air, antal sändningar och förbrukad budget.
7. Före fälttest eller driftsättning måste faktisk ERP verifieras, inklusive sändareffekt, antennförstärkning och kabelförluster.
8. Kodagenter får inte höja sändfrekvens, retry-gränser eller sändeffekt utan att samtidigt kontrollera dessa krav.

Detaljerad policy, beräkningar och implementeringskrav finns i `docs/06-radio-parametrar.md`. Protokollspecifika referenser finns i `docs/05-protokollspecifikation.md`.

## Obligatoriskt krav: verifiera istället för att anta (bänkdisciplin)

Följande krav är bindande för allt arbete som rör fysisk hårdvara, loggtolkning och verifieringsdomslut i detta repo.

1. Hårdvaruidentitet ska verifieras med kommando och output före åtgärd — kortmodell och variant (t.ex. Pico 2 vs Pico 2 W), portnummer, firmware-banner och körtillstånd. USB-strängar, minne från tidigare pass och antaganden om stabilitet gäller aldrig som identitet.
2. Portnummer, tillstånd och sidoeffekter av portöppning (reset, omsnumrering) ska bekräftas på nytt efter varje fysisk omkoppling. Inget portnummer får återanvändas över en ur-/inkoppling utan ny identifiering.
3. Högst en hypotesnivå i taget: varje påstående om hårdvarubeteende ska paras med det billigaste testet som kan döda det. Teoribyggen i flera led utan avgörande test är inte tillåtna som grund för domslut.
4. Domslut kräver tidsstämplad evidens: loggutdrag med klockslag, versions-/hash-identitet på körd firmware, samt vad som observerades var. Muntliga observationer gäller endast synkroniserat ("titta nu") och ska korreleras mot samtidig logg.
5. Fysiska fakta (kabeldragning, knapptryck, vad en display visar, vad en LED gör) ska efterfrågas hos operatören istället för att gissas. Operatörens svar gäller framför agentens teori vid motsägelse.
6. Misslyckade delsteg (timeout, uteblivet svar, avvikande output) ska redovisas som de är — aldrig övertolkas till bekräftelse. Frånvaro av fel är inte bevis för funktion.
7. Vid motsägelse mellan teori och observation vinner observationen alltid; teorin revideras, aldrig tvärtom.

## Agent skills

### Issue tracker

Issues bor i repots GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Standardvokabulär (needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` i roten (+ `docs/adr/` när det skapas). See `docs/agents/domain.md`.
