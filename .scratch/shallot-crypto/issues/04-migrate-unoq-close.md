# 04 — Migrera UNO-Q + stäng

**What to build:** MCU:n kör delad krypto; receivers dokumenterat
uteslutna; slutlig suite + sammansatt bänk bevisar avslutet.

**Blocked by:** 01 — Biblioteksskelett + KAT (bänk körs efter 02 och 03).

**Status:** code-done (bänkgrind ÖPPEN — kräver sammansatt bänk efter 02+03)

- [x] Inga lokala SHA/HMAC/KDF-kopior kvar i UNO-Q-mcu
- [x] Receivers + arkiv dokumenterat uteslutna (orörda)
- [x] Full suite grön (521 passed + 2 kända för-existerande fel)
- [x] En kryptoimplementation i aktiv firmware verifierad via guards
- [ ] Sammansatt bänk passerad (K1–K6-relevant: nyckellivscykel oförändrad)
