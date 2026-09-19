# 02 — Migrera PAW

**What to build:** PAW kör all krypto via ShallotCrypto — samma svar på
bänken som före, bevisat med bänkverifiering, separat revertbart.

**Blocked by:** 01 — Biblioteksskelett + KAT.

**Status:** code-done (bänkgrind ÖPPEN — kräver flash + challenge-response mot DEN)

- [x] Inga lokala SHA/HMAC/KDF-kopior kvar i PAW
- [x] Guards och mirrors uppdaterade, suite grön
- [ ] Bänkgrind passerad (challenge-response mot DEN)
- [x] Revertbar med en revert
