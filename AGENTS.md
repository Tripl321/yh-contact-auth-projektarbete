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
