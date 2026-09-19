# 05 — FIDO2: enda redaction-ägare, sedan verifier-kollaps

**What to build:** steg 1 (denna biljett): en redaction-modul som både
fido2_sanitize och mamabear konsumerar — divergent regex-risk borttagen
utan beteendeförändring. Steg 2 (separat): kollapsa Ceremony+backend
till ett verifier med mock/HW-capability.

**Blocked by:** None — can start immediately (steg 2 blockas av steg 1).

**Status:** done (steg 1; steg 2 formulerat nedan)

- [x] En redaction-ägare; båda konsumenterna migrerade
- [x] Maskningstester gröna, output identisk
- [x] Steg 2 formulerat som uppföljningsbiljett vid avslut

Uppföljning (steg 2, klart): HwBackend-stubben borttagen (ingen
anropade den — fabriken returnerade redan CtapHidBackend); ABC:t
behålls medvetet (MockBackend + CtapHidBackend är två verkliga
implementationer, ingen hypotetisk söm); server-side-vägran testlåst
mot CtapHidBackend; exakt-två-implementationer testlåst.
