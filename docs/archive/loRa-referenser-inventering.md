# 10 — Inventering av LoRa-referenser i dokumentation

> **Status:** Referensdokument | **Syfte:** Katalogisera och separera äldre (före pivot) från
> aktuella (post-pivot) LoRa-referenser i projektets dokumentation.
>
> **Pivotpunkt:** 2026-09-09 — `docs/architecture-pivot-2026-09-09.md`
> (git-commit `7e32395`). Från och med detta datum är UART (dockat) den
> primära autentiseringstransporten. LoRa är explicit ur scope för aktiva
> spår, och behålls endast i två framtida roller (SHALLOT OTA + TX-only
> larmkanal).

## Sammanfattningstabell

| Fil | Totalt LoRa-referenser | Äldre (före pivot) | Aktuella (post-pivot) |
|-----|-----------------------|---------------------|------------------------|
| `README.md` (rot) | 5 | 3 (rader 5, 8, 22) | 1 (rad 121) |
| `docs/01-kravspecifikation.md` | 17 | 15+ | 2 (AL-006, AL-007) |
| `docs/02-arkitektur.md` | 20+ | 20+ | 0 |
| `docs/03-komponentval.md` | 1 | 1 | 0 |
| `docs/04-kopplingsdokumentation.md` | 6 | 6 | 0 |
| `docs/06-radio-parametrar.md` | 10+ | 10+ | 0 |
| `docs/00-scope.md` | 5 | 0 | 5 |
| `docs/architecture-pivot-2026-09-09.md` | 8 | 0 | 8 |
| `docs/11-dockat-uart-protokoll.md` | 1 | 0 | 1 |
| `docs/12-envelope-protocol.md` | 1 | 0 | 1 |
| `docs/13-pro-53-fail-closed.md` | 5 | 0 | 4 (+1 referens) |
| `docs/14-provisioning-v2-design.md` | 2 | 0 | 2 |
| `docs/17-pro-98-paw-blocklist.md` | 1 | 1 (rad 49) | 0 |
| `docs/18-pro-94-security-review.md` | 2 | 0 | 2 |
| `docs/19-fido2-designspec.md` | 0 | 0 | 0 |
| `docs/README.md` | 4 | 3 (konsistenskontroll) | 1 (PRO-43 referens) |
| `docs/status/vecka-1-2026-09-05.md` | 4+ | 4+ | 0 |
| `docs/status/vecka-1-statusrapport.md` | 2+ | 2+ | 0 |
| `docs/templates/kopplingsdokumentation-template.md` | 6 | 6 | 0 |
| `plc/README.md` | 4 | 4 | 0 |
| `plc/den-main/README.md` | 2 | 0 | 2 |
| `id-kort/README.md` | 2 | 2 | 0 |
| `id-kort/paw-main/README.md` | 11+ | 10+ | 1 (rad 121) |
| **Totalt** | **110+** | **~95+** | **~15-20** |

---

## 1. Äldre referenser (före pivot, före 2026-09-09)

Dessa referenser beskriver LoRa som den primära autentiseringstransporten,
markerar LoRa-funktionalitet som "Implementerad", eller dokumenterar LoRa som
aktivt arbetsområde. Efter pivott är dessa **föråldrade / felaktiga** och bör
uppdateras för att återspegla den UART-first-arkitekturen.

### 1.1 `README.md` (rot)

| Rad | Innehåll (utdrag) | Problem |
|-----|-------------------|---------|
| 5 | `Challenge-response autentisering över LoRa P2P med AES-128 och HMAC-SHA256.` | Projektbeskrivning säger LoRa är primär transport — nu är det UART. |
| 8 | `två noder över LoRa-radio. En PLC (Raspberry Pi Pico 2) utmanar ett ID-kort` | Beskriver LoRa som kommunikationskanal. |
| 22 | `PLC skickar en nonce (slumpmässigt tal) over LoRa till ID-kortet` | Flödessteg 3 beskriver LoRa istället för UART. |

**Exakterade avsnitt:**

> *Rad 5:* "Challenge-response autentisering över LoRa P2P med AES-128 och HMAC-SHA256."
>
> *Rad 8:* "Ett IoT-säkerhetsprojekt som demonstrerar kryptografisk autentisering mellan två noder över LoRa-radio. En PLC (Raspberry Pi Pico 2) utmanar ett ID-kort (Adafruit Feather RP2350) med en nonce."
>
> *Rad 22:* "PLC skickar en nonce (slumpmässigt tal) over LoRa till ID-kortet"

**Rekommenderad åtgärd:** Uppdatera projektbeskrivning och kryptografiskt flöde att
använda UART (dockat) som primär transport. LoRa nämns endast som framtida
TX-only-larmkanal och SHALLOT OTA.

---

### 1.2 `docs/01-kravspecifikation.md` (v2.0, 2026-09-07)

Dokumentet är helt före pivot. Hela sektion 2.3 (FR-LR) handlar om LoRa som
primär transport och är markerad "Implementerad". Kraven FR-CR-002, FR-CR-004
refererar LoRa som transport.

| Rad | Kategori | Innehåll (utdrag) | Problem |
|-----|----------|-------------------|---------|
| 23 | FR-NP / systemöversikt | `PLC (edge enforcement-nod) — Raspberry Pi Pico 2 (RP2350) + Core1262 (SX1262 LoRa). Genererar nonce, skickar challenge över LoRa, verifierar HMAC, fattar fail-closed-beslut.` | Beskriver LoRa som primär transport. |
| 37 | Definition | `Challenge — Nonce som skickas från PLC till PAW över LoRa` | Definitionen refererar LoRa istället för UART. |
| 71 | FR-CR-002 | `PLC ska skicka challenge (nonce) till PAW över LoRa` | Status: Avgränsning (PRO-52) — men transporten är nu UART. |
| 73 | FR-CR-004 | `PAW ska returnera response (32 byte) till PLC över LoRa` | Status: Avgränsning (PRO-52) — men transporten är nu UART. |
| 78 | FR-CR-009 | `PLC:s challenge-response-protokoll över LoRa är framtida arbete` | Bör vara UART (PRO-52) som aktiv; LoRa som framtida. |
| 80–90 | 2.3 FR-LR (hel sektion) | `FR-LR-001 … FR-LR-007` — hela sektionen om LoRa P2P-kommunikation, markerad "Implementerad" | Hela sektionen beskriver LoRa som primär transport. |
| 84 | FR-LR-001 | `PLC och PAW ska kommunicera över LoRa P2P med Core1262 (SX1262)` | Status: Implementerad — felaktigt efter pivot. |
| 85 | FR-LR-002 | `Core1262 ska initieras via SPI1 med RadioLib-biblioteket` | Status: Implementerad — men LoRa är ur scope. |
| 86 | FR-LR-003 | `PLC ska kunna sända och ta emot LoRa-paket` | Status: Implementerad. |
| 87 | FR-LR-004 | `PAW ska kunna sända och ta emot LoRa-paket` | Status: Implementerat. |
| 88 | FR-LR-005 | `LoRa-kommunikationen ska vara dubbelriktad (bidirektionell)` | Status: Implementerad. |
| 89 | FR-LR-006 | `Paketformat ska definieras med fast struktur för challenge, response och status` | Status: Avgränsning (PRO-37). |
| 90 | FR-LR-007 | `Systemet ska hantera överföringsfel och retransmissioner` | Status: Avgränsning (PRO-41). |
| 101 | FR-SV-006 | `Displayen ska använda SPI0 (separat från LoRa SPI1)` | Refererar LoRa SPI1 som aktiv. |
| 136 | NFR-TIM-001 | `LoRa-challenge ska sändas och response mottagas inom 5 sekunder` | Status: Avgränsning (PRO-52) — transporten är nu UART. |
| 146 | NFR-RAD-001 | `LoRa-modul: Waveshare Core1262 (SX1262), 868/915 MHz` | Status: Implementerad. |
| 147 | NFR-RAD-002 | `LoRa ska köra i P2P-läge (ej LoRaWAN)` | Status: Implementerat. |
| 149 | NFR-RAD-004 | `RadioLib-biblioteket ska användas för LoRa-initiering` | Status: Implementerat. |
| 150 | NFR-RAD-005 | `Exakta LoRa-parametrar ... ska dokumenteras i 06-radio-parametrar` | Status: Avgränsning (PRO-43). |
| 184 | Kravsmatris | `FR-LR (LoRa-kommunikation) — 7 krav, 5 implementerade, 2 avgränsningar` | Markerek som 5/7 implementerade. |
| 202 | AL-001 | `Challenge-response-protokoll över LoRa är inte implementerat` | Bör referera UART istället. |
| 207 | AL-006 | `Paketformat för LoRa är inte formellt definierat` | Bör referera UART-protokollet. |
| 208 | AL-007 | `Felhantering och retransmission över LoRa är inte implementerad` | Bör referera UART-protokollet. |

**Exakterade avsnitt (nyckelpassage):**

> *Rad 23:* "2. **PLC (edge enforcement-nod)** — Raspberry Pi Pico 2 (RP2350) + Core1262 (SX1262 LoRa). Genererar nonce, skickar challenge över LoRa, verifierar HMAC, fattar fail-closed-beslut."
>
> *Sektion 2.3 (rader 80–90):*
> ```
> ### 2.3 LoRa-kommunikation (FR-LR)
>
> | FR-LR-001 | PLC och PAW ska kommunicera över LoRa P2P med Core1262 (SX1262) | Måste | T | Implementerad |
> | FR-LR-002 | Core1262 ska initieras via SPI1 med RadioLib-biblioteket | Måste | T | Implementerat |
> | FR-LR-003 | PLC ska kunna sända och ta emot LoRa-paket | Måste | T | Implementerat |
> | FR-LR-004 | PAW ska kunna sända och ta emot LoRa-paket | Måste | T | Implementerat |
> | FR-LR-005 | LoRa-kommunikationen ska vara dubbelriktad (bidirektionell) | Måste | D | Implementerat |
> | FR-LR-006 | Paketformat ska definieras med fast struktur ... | Måste | I | Avgränsning (PRO-37) |
> | FR-LR-007 | Systemet ska hantera överföringsfel och retransmissioner | Borde | T | Avgränsning (PRO-41) |
> ```
>
> *Sektion 3.3 (rader 146–150):*
> ```
> | NFR-RAD-001 | LoRa-modul: Waveshare Core1262 (SX1262), 868/915 MHz | Måste | I | Implementerat |
> | NFR-RAD-002 | LoRa ska köra i P2P-läge (ej LoRaWAN) | Måste | I | Implementerat |
> | NFR-RAD-004 | RadioLib-biblioteket ska användas för LoRa-initiering | Måste | I | Implementerat |
> | NFR-RAD-005 | Exakta LoRa-parametrar ... ska dokumenteras i 06-radio-parametrar | Borde | I | Avgränsning (PRO-43) |
> ```

**Rekommenderad åtgärd:** Uppdatera dokumentet så att:
- FR-CR-002/004 använder UART som transport (PRO-88/84)
- FR-LR-sektionen ersätts eller omskrivs för att beskriva LoRa endast som
  framtida SHALLOT OTA / TX-only-larmkanal (ej "Implementerad")
- NFR-RAD-sektionen markerar LoRa som "Avgränsning / framtida" istället för
  "Implementerad"
- Kravsmatrisen uppdateras: FR-LR-status 0/7 implementerat

---

### 1.3 `docs/02-arkitektur.md` (v2.0, 2026-09-07)

Dokumentet är helt före pivot. LoRa P2P är den primära transporten i alla
diagram och beskrivningar. Användar även "UNO Q" (efter pivot: "Mama Bear").

| Rad | Innehåll (utdrag) | Problem |
|-----|-------------------|---------|
| 32 | `PLC["PLC — Edge Enforcement<br/>RP2350 + Core1262 (LoRa)<br/>SPI1"]` | Mermaid-diagram, LoRa som roll. |
| 37 | `PLC -->|"LoRa P2P — Challenge<br/>(128-bit nonce)"\| PAW` | Primär transport är LoRa. |
| 38 | `PAW -->|"LoRa P2P — Response<br/>(HMAC-SHA256, 32 byte)"\| PLC` | Primär transport är LoRa. |
| 52 | `Hårdvara: Raspberry Pi Pico 2 (RP2350) + Waveshare Core1262 (SX1262 LoRa)` | Beskriver LoRa som aktiv. |
| 56 | `Status: SPI bring-up bekräftad, LoRa RX/TX fungerar` | Markerar LoRa som fungerande. |
| 61 | `SPI1: Core1262 LoRa (samma pin-konfiguration som PLC)` | Aktiv LoRa SPI. |
| 64 | `Status: E-Paper-drivrutin implementerad, LoRa RX/TX fungerar` | Markerar LoRa som fungerande. |
| 82 | `PLC->>PAW: LoRa — Challenge (nonce)` | Sequence-diagram, LoRa primär. |
| 84 | `PAW->>PLC: LoRa — Response (32 byte)` | Sequence-diagram, LoRa primär. |
| 88 | `PLC->>PAW: LoRa — Authenticated` | Sequence-diagram, LoRa primär. |
| 91 | `PLC->>PAW: LoRa — Failed (fail-closed)` | Sequence-diagram, LoRa primär. |
| 105 | `C -->|"HMAC-SHA256"\| E["Challenge-Response<br/>over LoRa"]` | Mermaid, LoRa som transport. |
| 162 | `### 6.1 PLC — Core1262 LoRa (SPI1)` | Pin-konfiguration för LoRa. |
| 174 | `### 6.2 PAW — Core1262 LoRa (SPI1)` | Pin-konfiguration för LoRa. |
| 199 | `START["Systemstart"] --> INIT["Initiera SPI1 + LoRa"]` | State machine initierar LoRa. |
| 204 | `CHALLENGE --> SEND["Skicka challenge<br/>over LoRa"]` | Challenge sänds över LoRa. |
| 221 | `LoRa-kommunikation fallerar | Neka access | Paketförlust eller interferens` | Fail-closed-scenario för LoRa. |
| 256 | `| LoRa \| RadioLib \| SPI1 via arduino-pico` | Byggmiljö tabell. |
| 290 | `### 11.2 LoRa-parametrar` | Hänvisar till dokument 06. |

**Exakterade avsnitt (nyckelpassage):**

> *Sektion 2 (rader 29–39):*
> ```mermaid
> graph TB
>     UNOQ["UNO Q<br/>STM32U585 + QRB2210<br/>Air-gapped provisioning hub"]
>     PLC["PLC — Edge Enforcement<br/>RP2350 + Core1262 (LoRa)<br/>SPI1"]
>     PAW["PAW — ID-bricka<br/>Feather RP2350 + Core1262 (SPI1)<br/>+ e-Paper (SPI0)"]
>     ...
>     PLC -->|"LoRa P2P — Challenge<br/>(128-bit nonce)"| PAW
>     PAW -->|"LoRa P2P — Response<br/>(HMAC-SHA256, 32 byte)"| PLC
> ```
>
> *Sektion 3 (rader 70–94):* Sequence-diagram visar hela autentiseringsflödet
> över LoRa: Challenge → Response → Authenticated/Failed.
>
> *Sektion 7 (rader 198–212):* State machine initierar "SPI1 + LoRa" som
> första steg. Fail-closed-scenarier inkluderar "LoRa-kommunikation fallerar".

**Rekommenderad åtgärd:** Omskriv arkitekturen så att:
- UART (dockat) är den primära auth-transporten (PRO-88/84)
- LoRa nämns endast som SHALLOT OTA (framtida) och TX-only-larmkanal
- "UNO Q" byts ut mot "Mama Bear" enligt pivot
- State machine initierar UART istället för LoRa
- Sektion 6.1/6.2 behandlar UART-pinnar istället för LoRa SPI
- Sektion 11.2 hänvisar till TX-only-larmkanal-parametrar i stället

---

### 1.4 `docs/03-komponentval.md` (2026-09-05)

| Rad | Innehåll (utdrag) | Problem |
|-----|-------------------|---------|
| 10 | `LoRa-modul | Waveshare | Core1262-868M | 2 | | |` | Listar LoRa-modul som komponent utan att ange att det är för framtida TX-only/OTA. |

**Exakterat avsnitt:**

> ```
> | LoRa-modul | Waveshare | Core1262-868M | 2 | | | |
> ```

**Rekommenderad åtgärd:** Annotera att Core1262-modulen används för framtida
TX-only-larmkanal och SHALLOT OTA, inte för primär autentisering.

---

### 1.5 `docs/04-kopplingsdokumentation.md` (2026-09-05)

| Rad | Innehåll (utdrag) | Problem |
|-----|-------------------|---------|
| 17–23 | `SPI1: Core1262 (LoRa)` pin-tilldelning för PAW | Primär LoRa-koppling. |
| 36–42 | `SPI1: Core1262 (LoRa)` pin-tilldelning för Edge | Primär LoRa-koppling. |
| 46 | `- SPI1: Core1262` | Endast LoRa-buss. |
| 57 | `Autentisering (Edge <-> PAW): LoRa utmaning/svar` | Beskriver LoRa som auth-transport. |
| 61 | `### LoRa Kommunikation Fel` | Felsökning för LoRa-samband. |

**Exakterade avsnitt:**

> *Rad 57:* "2. Autentisering (Edge <-> PAW): LoRa utmaning/svar"
>
> *Rader 61–64:* "### LoRa Kommunikation Fel — Verifiera SPI-anslutningar, Kontrollera RadioLib-konfiguration, Testa med kort avstånd"

**Rekommenderad åtgärd:** Omskriv kopplingsdokumentationen för att UART (pogo-pins)
är den primära kopplingen. LoRa-kopplingarna kan behandlas som referens för
framtida TX-only-larmkanal.

---

### 1.6 `docs/06-radio-parametrar.md`

Ingen tidsstämpel, men dokumentet beskriver LoRa-parametrar som om de är
aktivt konfigurerade och i drift. Efter pivot är LoRa endast en framtida
TX-only-larmkanal.

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 5 | `Dessa parametrar är konfigurerade och beslutade enligt PRO-78.` | Beskriver som aktivt beslutat. |
| 7–16 | Tabell med LoRa-parametrar (frekvens, BW, SF, etc.) | Markerar som "konfigurerade" snarare än framtida. |
| 18–28 | Fälttestresultat — "Ej mätt" | Om LoRa är ur scope bör dessa vara framtida. |
| 30–34 | Planerade testmetoder för LoRa | Bör annoteras som framtida TX-only/OTA. |

**Exakterat avsnitt:**

> ```
> | Frekvens | 868.1 MHz | EU ISM-band |
> | Bandbredd | 125 kHz | |
> | Spreading Factor | 7 | |
> | Coding Rate | 4/5 | |
> | Sändeffekt | 20 dBm | |
> | Sync Word | 0x12 | Privat användning, inte LoRaWAN-standard |
> ```

**Rekommenderad åtgärd:** Annotera att dessa parametrar är avsedda för den
framtida TX-only-larmkanalen och/eller SHALLOT OTA, inte för primär auth.

---

### 1.7 `docs/status/vecka-1-2026-09-05.md` (2026-09-05)

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 28 | `### Epic 2: LoRa P2P-kommunikation` | Beskriver LoRa som huvudepic. |
| 29–35 | PRO-35 till PRO-41 — LoRa P2P tasks, alla "✅ Klar" | Markerar som genfergärdiga. |
| 54–56 | `### Epic 2: LoRa P2P — PRO-42, PRO-43` | Planerar LoRa-dokumentation som aktivt. |
| 105 | `Epic 2: LoRa P2P | 10 | 7 | 0 | 70%` | Metrik för LoRa som huvudfokus. |
| 139 | `Vecka 1 har varit framgångsrik med alla hållvaru- och LoRa-tasks klara.` | Sammanfattar LoRa som primär. |
| 181 | `Slutför LoRa dokumentation (PRO-42-43)` | Planerar LoRa-dokumentation som aktivt. |

**Exakterat avsnitt:**

> *Rad 139:* "Vecka 1 har varit framgångsrik med alla hårdvaru- och LoRa-tasks klara."

**Rekommenderad åtgärd:** Denna rapport är en historisk statusrapport från innan
pivot. Den bör arkiveras som historisk referens. Se `docs/archive/` — denna
rapport bör länkas därifrån.

---

### 1.8 `docs/status/vecka-1-statusrapport.md` (2026-09-05)

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 34 | `### Epic 2: LoRa P2P-kommunikation` | Huvudepic. |
| 35–36 | PRO-35 till PRO-41 klara, PRO-42/43 i backlog | LoRa som aktiv epic. |
| 39 | `Grundläggande LoRa P2P kommunikation fungerar` | Markerar som fungerande. |
| 139 | `Vecka 1 har varit framgångsrik med alla hårdvaru- och LoRa-tasks klara.` | Samma som ovan. |

**Rekommenderad åtgärd:** Historisk rapport — arkivera. Se `docs/archive/`.

---

### 1.9 `docs/README.md` (dokumentationsindex)

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 48 | `LoRa P2P (challenge-response) \| FR-CR-002, FR-CR-004, FR-LR-001 \| Kapitel 3, 11 \| Konsistent` | Konsistenskontroll behandlar LoRa som primär transport. |
| 50 | `SPI1 (Core1262) \| FR-LR-002, NFR-RAD-003 \| Kapitel 6.1, 6.2 \| Konsistent` | Behandlar LoRa SPI som aktiv. |
| 68 | `LoRa-parametrar \| 01 kräver dokumentation ... \| PRO-43 (2026-09-12)` | Behandlar som aktiv uppgift. |

**Rekommenderad åtgärd:** Uppdatera konsistenskontrollen för att UART är
primär transport. LoRa-parametrar länkas till framtida TX-only/OTA.

---

### 1.10 `docs/templates/kopplingsdokumentation-template.md`

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 26–33 | `LoRa Core1262 (SPI1)` koppling för Edge | Mall inkluderar LoRa som primär. |
| 37–44 | `LoRa Core1262 (SPI1)` koppning för PAW | Mall inkluderar LoRa som primär. |
| 57 | `Autentisering (Edge <-> PAW): LoRa utmaning/svar` | Beskriver LoRa som auth. |
| 61–64 | `LoRa Kommunikation Fel` felsökning | LoRa-felsökning som primär. |

**Rekommenderad åtgärd:** Uppdatera mall till UART (pogo-pins) som primär
koppling. LoRa-kopplingar kan vara en appendage/appendix för framtida användning.

---

### 1.11 `plc/README.md`

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 3 | `Firmware for PLC-noden: Raspberry Pi Pico 2 (RP2350A) med Waveshare Core1262-868M (SX1262 LoRa, 868 MHz).` | Beskriver LoRa som primär. |
| 7 | `Skicka challenge (nonce) till ID-kort over LoRa P2P` | LoRa som transport. |
| 9 | `Drivare for SX1262 via RadioLib over SPI1` | Aktiv LoRa-drivare. |

**Exakterat avsnitt:**

> *Rad 7:* "- Skicka challenge (nonce) till ID-kort over LoRa P2P"

**Rekommenderad åtgärd:** Uppdatera att PLC primärt använder UART för
dock-autentisering (PRO-88). LoRa behålls för TX-only-larmkanal (framtida).

---

### 1.12 `id-kort/README.md`

| Rad | Innehåll | Problem |
|-----|----------|---------|
| 7 | `Ta emot challenge (nonce) fran PLC over LoRa P2P` | LoRa som transport. |
| 59 | `RadioLib (jgromes) - for SX1262 LoRa (när du ersätter mock-implementationen)` | Påminner om att ersätta mock med riktigt LoRa. |

**Rekommenderad åtgärd:** Uppdatera att PAW primärt använder UART-responder
(PRO-84) för dock-autentisering. LoRa är framtida.

---

### 1.13 `id-kort/paw-main/README.md`

| Rad | Innehäll | Problem |
|-----|----------|---------|
| 8 | `PRO-50: Beräknar HMAC-SHA256 svar på LoRa challenge från PLC` | LoRa som challenge-transport. |
| 10 | `PRO-58: LoRa P2P kommunikation med PLC (simulerad för test)` | LoRa som aktiv funktion. |
| 19 | `| **LoRa SPI1** \| GP10 (CLK), GP11 (MOSI), GP28 (MISO) \| Core1262 |` | LoRa SPI som aktiv. |
| 35 | `RadioLib (jgromes) - för SX1262 LoRa (när du ersätter mock-implementationen)` | Påminner om riktigt LoRa. |
| 64 | `; Bibliotek (avkommentera när du använder riktig LoRa)` | Framtida LoRa. |
| 101 | `Components: Core1262 LoRa + e-Paper` | Beskriver LoRa som aktiv komponent. |
| 104 | `[PRO-58] Initializing LoRa...` | Initierar LoRa som aktiv. |
| 132 | `2. Anslut LoRa-moduler (samma frekvens: 868MHz)` | LoRa-installation. |
| 178–180 | `TODO: Ersätt MockLoRa, Lägg till LoRa-konfiguration, Implementera felhantering` | LoRa som aktiv utveckling. |

**Exakterade avsnitt:**

> *Rad 10:* "- **PRO-58**: LoRa P2P kommunikation med PLC (simulerad för test)"
>
> *Rader 178–180:*
> ```
> - [ ] Ersätt `MockLoRa` med riktig RadioLib implementation
> - [ ] Lägg till LoRa-konfiguration (frekvens, bandwidth, etc.)
> - [ ] Implementera riktig felhantering för LoRa
> ```

**Rekommenderad åtgärd:** Annotera att PRO-50/PRO-58 är framtida SHALLOT OTA.
Uppdatera TODO att LoRa-konfiguration är framtida TX-only-larmkanal, inte aktiv
utveckling.

---

## 2. Aktuella referenser (post-pivot, 2026-09-09)

Dessa referenser är korrekta och återspeglar den nuvarandearkitekturen där LoRa
är uttryckligt ur scope för aktiva spår.

### 2.1 `docs/00-scope.md` (2026-09-09)

| Rad | Innehåll | Status |
|-----|----------|--------|
| 3 | `**Status:** Aktiv 2026-09-09 \| Ersätter tidigare LoRa-felsökning som spår.` | ✓ Korrekt |
| 12 | `**Transporten är UART (Serial1) — LoRa är explicit ur scope.**` | ✓ Korrekt |
| 22–24 | `LoRa-radiofelsökning är **explicit ur scope** tills en framtida uppgift riktar TX-only-larmkanalen.` | ✓ Korrekt |
| 25–26 | `Ett LoRa -2-initieringsfel är icke-blockerande och loggas **högst en gång**` | ✓ Korrekt |
| 27–28 | `Rapporter hålls till det aktiva spåret; LoRa listas endast när det direkt blockerar ett bygge.` | ✓ Korrekt |

### 2.2 `docs/architecture-pivot-2026-09-09.md` (2026-09-09)

| Rad | Innehåll | Status |
|-----|----------|--------|
| 5 | `Primär autentiseringstransport för SHALLOT ändras från LoRa P2P till kontaktbaserad dockning` | ✓ Korrekt |
| 24 | `### SHALLOT Over the Air (LoRa)` | ✓ Beskriver framtida roll |
| 26 | `PAW autentiseras över LoRa P2P — samma kryptologik, annan transport` | ✓ Framtida roll |
| 30 | `### LoRa TX-only larmkanal (båda varianterna)` | ✓ Framtida roll |
| 32 | `DEN sänder LoRa TX-only som larm- och heartbeat-kanal` | ✓ Framtida roll |
| 61 | `PRO-86: LoRa TX-only larmkanal med cover traffic` | ✓ Framtida spår |

### 2.3 `docs/11-dockat-uart-protokoll.md` (2026-09-09)

| Rad | Innehåll | Status |
|-----|----------|--------|
| 6 | `över pogo-pins/USB-C; LoRa används ej.` | ✓ Korrekt |

### 2.4 `docs/12-envelope-protocol.md`

| Rad | Innehåll | Status |
|-----|----------|--------|
| 12 | `Non-goals: LoRa transport, multi-device fan-out, key rotation over the air` | ✓ Korrekt |

### 2.5 `docs/13-pro-53-fail-closed.md`

| Rad | Innehåll | Status |
|-----|----------|--------|
| 5 | `UART is the current and only in-scope transport for DEN↔PAW docked authentication. **LoRa is explicitly out of scope.**` | ✓ Korrekt |
| 135–136 | `LoRa is explicitly out of scope. This is documented in: docs/00-scope.md — LoRa-radiofeldsökning är explicit ur scope` | ✓ Korrekt |
| 166 | `**LoRa is out of scope.** No LoRa behavior is present in the DEN firmware, the PAW UART responder, or the protocol.` | ✓ Korrekt |

### 2.6 `docs/14-provisioning-v2-design.md`

| Rad | Innehåll | Status |
|-----|----------|--------|
| 12 | `Non-goals: LoRa transport, multi-device fan-out, key rotation over the air` | ✓ Korrekt |

### 2.7 `plc/den-main/README.md`

| Rad | Innehäll | Status |
|-----|----------|--------|
| 8 | `LoRa is explicitly out of scope.` | ✓ Korrekt |
| 63 | `Out of scope here: LoRa, e-paper, pogo-dock mechanics (PRO-85), PAW firmware.` | ✓ Korrekt |

### 2.8 Root `README.md` (rad 121)

| Rad | Innehäll | Status |
|-----|----------|--------|
| 121 | `LoRa är utanför aktiv MVP och hanteras inte av CLI:t.` | ✓ Korrekt |

### 2.9 `docs/18-pro-94-security-review.md` (2026-09-14)

| Rad | Innehäll | Status |
|-----|----------|--------|
| 49 | `PAW \| keyStored=false at boot → STATE_WAITING_FOR_KEY; dock/LoRa auth rejected` | ✓ Refererar båda transporterna, dock/LoRa |
| 143 | `LoRa link budget / reliability \| RF environment testing` | ✓ Framtida RF-testning notering |

**Observera:** Rad 49 använder "dock/LoRa" i en tabell om PAW:s beteende vid
boot. Efter pivot är dock-autentisering (UART) den enda aktiva transporten.
"LoRa auth" bör annoteras som framtida/SHALLOT OTA.

### 2.10 `docs/17-pro-98-paw-blocklist.md`

| Rad | Innehäll | Status |
|-----|----------|--------|
| 49 | `PAW \| keyStored=false at boot → STATE_WAITING_FOR_KEY; dock/LoRa auth rejected` | ⚠️ Samma mönster som 18-pro-94. |

**Observera:** Samma tabellrad som i 18-pro-94. Bör annoteras som ovan.

---

## 3. Sammanfattning — vad som behöver uppdateras

| Prioritet | Dokument | Åtgärd |
|-----------|----------|--------|
| Hög | `docs/02-arkitektur.md` | Omskriv hela dokumentet: UART som primär transport, LoRa som framtida OTA/TX-only. Byt "UNO Q" → "Mama Bear". |
| Hög | `docs/01-kravspecifikation.md` | Uppdatera FR-CR-002/004 till UART. Omskriv FR-LR-sektion. NFR-RAD → framtiga. Kravsmatris → 0/7 FR-LR implementerade. |
| Hög | `README.md` (rot) | Uppdatera projektbeskrivning och flöde: UART istället för LoRa som primär. |
| Medel | `docs/06-radio-parametrar.md` | Annotera som framtiva TX-only-larmkanalparametrar. |
| Medel | `docs/04-kopplingsdokumentation.md` | Omskriv för UART (pogo-pins) som primär koppling. |
| Medel | `docs/templates/kopplingsdokumentation-template.md` | Samma som ovan — mall uppdateras. |
| Medel | `docs/03-komponentval.md` | Annotera Core1262 som framtida TX-only/OTA. |
| Medel | `plc/README.md` | Uppdatera att UART är primär, LoRa är framtida. |
| Medel | `id-kort/README.md` | Uppdatera att UART-responder är primär, LoRa är framtida. |
| Medel | `id-kort/paw-main/README.md` | Annotera PRO-50/58 som framtiga SHALLOT OTA. Uppdatera TODO-listan. |
| Låg | `docs/README.md` | Uppdatera konsistenskontroll och dokumentstatus. |
| Låg | `docs/status/vecka-1-2026-09-05.md` | Markera som historisk (före pivot). Länk till arkiv. |
| Låg | `docs/status/vecka-1-statusrapporter.md` | Markera som historisk (före pivot). Länk till arkiv. |

## 4. Historiska referenser (arkiv)

Följande dokument är historiska statusrapporter från innan arkitekturpivott
(2026-09-09). De bevaras för referens men bör annoteras med ett avstängnings-
meddelande:

  - `docs/status/vecka-1-2026-09-05.md` — Veckorapport som beskriver LoRa P2P
  som primär transport. Gällt före pivot.
- `docs/status/vecka-1-statusrapport.md` — Statusrapport som listar
  "LoRa P2P" som aktiv epic. Gällt före pivot.

Dessa dokument har kopierats till `docs/archive/` för att bevara dem separat
från aktiv dokumentation.
