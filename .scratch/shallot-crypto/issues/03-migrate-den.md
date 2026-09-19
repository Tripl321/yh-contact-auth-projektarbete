# 03 — Migrera DEN

**What to build:** DEN kör all krypto via ShallotCrypto — samma
fail-closed-beteende på bänken som före, separat revertbart.

**Blocked by:** 01 — Biblioteksskelett + KAT (bänk körs efter 02).

**Status:** ready-for-agent

- [ ] Inga lokala SHA/HMAC/KDF-kopior kvar i DEN
- [ ] Guards och mirrors uppdaterade, suite grön
- [ ] Bänkgrind passerad (deny/agent-vägar oförändrade)
- [ ] Revertbar med en revert
