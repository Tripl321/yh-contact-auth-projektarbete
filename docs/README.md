# SHALLOT — Dokumentation

| Fält | Värde |
|------|-------|
| Version | 2.0 |
| Status | Aktiv |
| Datum | 2026-09-07 |
| Ansvarig | Johannes Olerås |

---

## Dokumentöversikt

| Nr | Dokument | Status | Linear | Deadline |
|----|----------|--------|--------|---------|
| 00 | Scope (post-pivot) | v1.0 — Aktiv | — | — |
| 01 | Kravspecifikation | v2.0 — Aktiv | PRO-30 | 2026-09-04 |
| 02 | Arkitektur | v2.0 — Aktiv | PRO-31 | 2026-09-04 |
| 03 | Komponentval | v1.0 — Utkast | PRO-32 | 2026-09-05 |
| 04 | Kopplingsdokumentation | v1.0 — Utkast | PRO-33 | 2026-09-05 |
| 05 | Protokollspecifikation | Ej påbörjad | PRO-42 | 2026-09-12 |
| 06 | Radio-parametrar | Ej påbörjad | PRO-43 | 2026-09-12 |
| 07 | Säkerhetsdesign | Ej påbörjad | PRO-54 | 2026-09-19 |
| 08 | Hotmodellering | Utkast (manuell, se docs/08-hotmodellering.md) | PRO-55 | 2026-09-19 |
| 09 | Integrationsbeskrivning | Ej påbörjad | PRO-67 | 2026-09-22 |
| 10 | Resultat och reflektion | Ej påbörjad | PRO-68 | 2026-09-23 |
| 11 | Dockat UART-protokoll PAW↔DEN | v1.0 — Utkast | PRO-87 | 2026-09-12 |

---

## Konsistenskontroll 01 <-> 02

Granskning av överensstämmelse mellan kravspecifikation (01) och arkitektur (02).

### Enheter

| Enhet | 01 Kravspecifikation | 02 Arkitektur | Status |
|-------|---------------------|---------------|--------|
| UNO Q | FR-NP-001 till FR-NP-012 | Kapitel 5 (trelagersmodell) | Konsistent |
| PLC | FR-CR, FR-LR, FR-FC | Kapitel 2.1, 6.1, 7 | Konsistent |
| PAW | FR-CR, FR-LR, FR-SV, FR-FC | Kapitel 2.1, 6.2, 6.3, 8 | Konsistent |

### Kommunikation

| Protokoll | 01 Kravspecifikation | 02 Arkitektur | Status |
|-----------|---------------------|---------------|--------|
| UART (nyckeldistribution) | FR-NP-003, FR-NP-004 | Kapitel 3, 4 | Konsistent |
| LoRa P2P (challenge-response) | FR-CR-002, FR-CR-004 | Kapitel 3, 11 | Konsistent |
| SPI1 (Core1262) | FR-LR-002 | Kapitel 6.1, 6.2 | Konsistent |
| SPI0 (e-Paper) | FR-SV-006 | Kapitel 6.3 | Konsistent |

### Säkerhet

| Egenskap | 01 Kravspecifikation | 02 Arkitektur | Status |
|----------|---------------------|---------------|--------|
| TRNG nyckelgenerering | FR-NP-001, NFR-SEC-005 | Kapitel 4, 5 | Konsistent |
| SRAM nyckellagring | FR-NP-007 till FR-NP-010 | Kapitel 4.1 | Konsistent |
| HMAC-SHA256 | FR-CR-003, FR-CR-005 | Kapitel 3, 11 | Konsistent |
| Fail-closed | FR-FC-001 till FR-FC-007 | Kapitel 7 | Konsistent |
| Sekretess (e-Paper) | FR-SV-003, FR-SV-004 | Kapitel 8 | Konsistent |
| Audit log | FR-NP-006, NFR-SEC-007 | Kapitel 5 | Konsistent |

---

## Historik

| Version | Datum | Ändring |
|---------|-------|---------|
| 1.0 | 2026-09-04 | Första utkast |
| 2.0 | 2026-09-07 | Konsistenskontroll tillagd. |
