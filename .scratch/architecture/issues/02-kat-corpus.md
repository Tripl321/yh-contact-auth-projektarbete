# 02 — Gemensamt KAT-corpus, guards opportunistiskt

**What to build:** ett versionerat KAT-corpus som alla beteendetester
konsumerar; grep-guards migreras per modul vid beröring, ingen big-bang.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] Corpus-fil med vektorer + konsument i pytest
- [ ] Minst en modul migrerad från grep-guard som bevis
- [ ] Inga nya grep-guards tillkommer (guard-test på guards)
