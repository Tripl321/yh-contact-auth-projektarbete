# 03 — Migrera DEN

**What to build:** DEN kör all krypto via ShallotCrypto — samma
fail-closed-beteende på bänken som före, separat revertbart.

**Blocked by:** 01 — Biblioteksskelett + KAT (bänk körs efter 02).

**Status:** code-done (bänkgrind ÖPPEN — kräver flash + deny/agent-verifiering)

- [x] Inga lokala SHA/HMAC/KDF-kopior kvar i DEN
- [x] Guards och mirrors uppdaterade, suite grön
- [ ] Bänkgrind passerad (deny/agent-vägar oförändrade)
- [x] Revertbar med en revert
