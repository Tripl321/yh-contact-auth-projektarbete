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
| 01 | Kravspecifikation | v2.0 — Aktiv | PRO-30 | 2026-09-04 |
| 02 | Arkitektur | v2.0 — Aktiv | PRO-31 | 2026-09-04 |
| 03 | Komponentval | v1.0 — Utkast | PRO-32 | 2026-09-05 |
| 04 | Kopplingsdokumentation | v1.0 — Utkast | PRO-33 | 2026-09-05 |
| 05 | Protokollspecifikation | Ej påbörjad | PRO-42 | 2026-09-12 |
| 06 | Radio-parametrar | Ej påbörjad | PRO-43 | 2026-09-12 |
| 07 | Säkerhetsdesign | Ej påbörjad | PRO-54 | 2026-09-19 |
| 08 | Hotmodellering | Ej påbörjad | PRO-55 | 2026-09-19 |
| 09 | Integrationsbeskrivning | Ej påbörjad | PRO-67 | 2026-09-22 |
| 10 | Resultat och reflektion | Ej påbörjad | PRO-68 | 2026-09-23 |

---

## Konsistenskontroll 01 <-> 02

Granskning av överensstämmelse mellan kravspecifikation (01) och arkitektur (02):

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
| LoRa P2P (challenge-response) | FR-CR-002, FR-CR-004, FR-LR-001 | Kapitel 3, 11 | Konsistent |
| SPI1 (Core1262) | FR-LR-002, NFR-RAD-003 | Kapitel 6.1, 6.2 | Konsistent |
| SPI0 (e-Paper) | FR-SV-006 | Kapitel 6.3 | Konsistent |

### Säkerhet

| Egenskap | 01 Kravspecifikation | 02 Arkitektur | Status |
|----------|---------------------|---------------|--------|
| TRNG nyckelgenerering | FR-NP-001, NFR-SEC-005 | Kapitel 4, 5 | Konsistent |
| SRAM nyckellagring | FR-NP-007 till FR-NP-010 | Kapitel 4.1 | Konsistent |
| HMAC-SHA256 | FR-CR-003, FR-CR-005, NFR-SEC-004 | Kapitel 3, 11 | Konsistent |
| Fail-closed | FR-FC-001 till FR-FC-007 | Kapitel 7 | Konsistent |
| Sekretess (e-Paper) | FR-SV-003, FR-SV-004, NFR-PRV-001 | Kapitel 8 | Konsistent |
| Audit log (avtryck) | FR-NP-006, NFR-SEC-007 | Kapitel 5 | Konsistent |

### Identifierade luckor

| Lucka | Beskrivning | Åtgärd |
|-------|-------------|--------|
| Paketformat | 01 kräver definierat format (FR-LR-006), 02 hänvisar till dokument 05 | PRO-37 (2026-09-08) |
| LoRa-parametrar | 01 kräver dokumentation (NFR-RAD-005), 02 hänvisar till dokument 06 | PRO-43 (2026-09-12) |
| Felhantering | 01 kräver retransmission (FR-LR-007), 02 inte detaljerad | PRO-41 (2026-09-12) |
| NFC/RFID | 01 har avgränsning (AL-008), 02 kapitel 12.1 beskriver plan | Ej planerad i sprint |

---

## Saknade förutsättningar

| Förutsättning | Status | Påverkan |
|---------------|--------|---------|
| Challenge-response implementerad | Ej påbörjad (PRO-49/50/51/52/53) | Blockerar PRO-53, PRO-61 |
| Paketformat definierat | Ej påbörjad (PRO-37) | Blockerar PRO-38/39/40 |
| Felhantering implementerad | Ej påbörjad (PRO-41) | Blockerar PRO-61 |
| Säkerhetsdesign dokumenterad | Ej påbörjad (PRO-54) | Blockerar PRO-55, PRO-63 |
| NFC/RFID-komponent vald | Ej påbörjad | Blockerar AL-008 |

---

## Dokumentationsstatus per sprint

### Sprint 1 (v36, 2026-09-01 till 2026-09-07)

| Dokument | Startstatus | Slutstatus |
|----------|-------------|------------|
| 01 Kravspecifikation | v1.0 | v2.0 |
| 02 Arkitektur | v1.0 | v2.0 |
| docs/README | v1.0 | v2.0 |
| 03 Komponentval | v1.0 | v1.0 (oförändrad) |
| 04 Kopplingsdokumentation | v1.0 | v1.0 (oförändrad) |

### Sprint 2 (v37, 2026-09-08 till 2026-09-14)

| Dokument | Planerad status |
|----------|-----------------|
| 05 Protokollspecifikation | v1.0 (PRO-42) |
| 06 Radio-parametrar | v1.0 (PRO-43) |

---

## Historik

| Version | Datum | Ändring |
|---------|-------|---------|
| 1.0 | 2026-09-04 | Första utkast |
| 2.0 | 2026-09-07 | Konsistenskontroll mellan 01 och 02 tillagd. Dokumentstatus uppdaterad. Saknade förutsättningar identifierade. Sprint-status tillagd. |
