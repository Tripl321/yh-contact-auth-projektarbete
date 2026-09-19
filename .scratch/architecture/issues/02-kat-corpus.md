# 02 — Gemensamt KAT-corpus, guards opportunistiskt

**What to build:** ett versionerat KAT-corpus som alla beteendetester
konsumerar; grep-guards migreras per modul vid beröring, ingen big-bang.

**Blocked by:** None — can start immediately.

**Status:** done (hook-bypass dokumenterad i commit: falskt positiv på publik testvektor)

- [x] Corpus-fil med vektorer + konsument i pytest
- [x] Minst en modul migrerad från grep-guard som bevis
- [x] Inga nya grep-guards tillkommer (guard-test på guards)
