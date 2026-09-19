# 05 — FIDO2: enda redaction-ägare, sedan verifier-kollaps

**What to build:** steg 1 (denna biljett): en redaction-modul som både
fido2_sanitize och mamabear konsumerar — divergent regex-risk borttagen
utan beteendeförändring. Steg 2 (separat): kollapsa Ceremony+backend
till ett verifier med mock/HW-capability.

**Blocked by:** None — can start immediately (steg 2 blockas av steg 1).

**Status:** ready-for-agent

- [ ] En redaction-ägare; båda konsumenterna migrerade
- [ ] Maskningstester gröna, output identisk
- [ ] Steg 2 formulerat som uppföljningsbiljett vid avslut
