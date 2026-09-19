# 01 — Biblioteksskelett + KAT

**What to build:** ett byggt, testat `libraries/ShallotCrypto`-bibliotek
(HMAC-SHA256 32 byte, båda KDF:erna, intern volatile wipe,
`ct_compare`, KAT-vektorer) som ingen firmware ännu använder — noll
beteendeförändring.

**Blocked by:** None — can start immediately.

**Status:** done (kod + KAT gröna; bänk ej tillämplig — används av ingen)

- [x] Biblioteket bygger i CI via befintligt `libraries/`-mönster
- [ ] KAT-vektorer bevisar HMAC/KDF/jämförelse mot oberoende oracle
- [ ] Wipe-garantin är testlåst i modulen
- [ ] Jämförelse dupliceras INTE: `den_ct_compare` har redan ett hem i
  DenUartProtocol (verifierat) — modulen dokumenterar återanvändning
- [ ] Ingen firmware-fil importerar det ännu
