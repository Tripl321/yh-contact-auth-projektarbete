# Statusuppdatering Vecka 1 - SHALLOT Projekt

## Rapportinformation
- **Projekt**: SHALLOT
- **Period**: 2026-08-29 till 2026-09-04
- **Rapportdatum**: 2026-09-05
- **Författare**: Johannes Olerås
- **Nästa rapport**: 2026-09-13 (Vecka 2)

## Sammanfattning

### Totalt
- **Total tasks**: 71
- **Klara**: 23 (32%)
- **Pågående**: 2 (3%)
- **Backlog**: 46 (65%)

### Prioritetsfördelning
- **Urgent**: 8 tasks
- **High**: 32 tasks
- **Medium**: 26 tasks

## Epic Status

### Epic 0: Projektplanering
- **Status**: 100% klar
- **Klara**: PRO-15, PRO-16, PRO-17, PRO-18, PRO-19, PRO-20, PRO-21, PRO-22

### Epic 1: Miljö & Hårdvara
- **Status**: 100% klar
- **Klara**: PRO-23, PRO-24, PRO-25, PRO-26, PRO-27, PRO-28, PRO-29
- **Notering**: Alla SPI bring-up tasks klara

### Epic 2: LoRa P2P-kommunikation
- **Status**: 85% klar
- **Klara**: PRO-35, PRO-36, PRO-37, PRO-38, PRO-39, PRO-40, PRO-41
- **Pågående**: 0
- **Backlog**: PRO-42, PRO-43 (dokumentation)
- **Notering**: Grundläggande LoRa P2P kommunikation fungerar

### Epic 3: Krypto & Autentisering
- **Status**: 0% klar - **KRITISK VÄG**
- **Pågående**: 0
- **Backlog**: PRO-45, PRO-46, PRO-47, PRO-48, PRO-49, PRO-50, PRO-51, PRO-52, PRO-53
- **Risk**: **HÖG** - Bör startas omedelbart för att hinna till presentation 25 sep

### Epic 4: E-Paper & Integration
- **Status**: 20% klar
- **Klara**: PRO-57
- **Backlog**: PRO-58, PRO-59, PRO-60, PRO-61, PRO-62, PRO-63
- **Notering**: Drivrutin klar, statusvisning och tester återstår

## Veckans Framsteg

### Klara denna vecka
- ✅ PRO-25: Koppla edge enforcement-nod breadboard (PLC)
- ✅ PRO-26: Koppla PAW breadboard (ID-bricka)
- ✅ PRO-27: SPI bring-up Core1262 edge enforcement
- ✅ PRO-28: SPI bring-up Core1262 PAW
- ✅ PRO-29: SPI bring-up e-Paper PAW
- ✅ PRO-35: RadioLib initiering edge enforcement
- ✅ PRO-36: RadioLib initiering PAW
- ✅ PRO-37: Definiera paketformat
- ✅ PRO-38: Implementera sändare edge enforcement
- ✅ PRO-39: Implementera mottagare PAW
- ✅ PRO-40: Implementera dubbelriktad kommunikation
- ✅ PRO-41: Felhantering och retningar
- ✅ PRO-57: E-Paper drivrutin med privacy masking

### Påbörjade denna vecka
- 🔄 PRO-32: Skriv komponentval (Påbörjad 2026-09-05)
- 🔄 PRO-33: Skriv kopplingsdokumentation (Påbörjad 2026-09-05)

## Risker och Problem

### 🔴 Kritiska Risker
1. **Epic 3 försenad**
   - Ingen utveckling påbörjad än
   - 9 tasks i backlog
   - Presentation om 20 dagar
   - **Åtgärd**: Starta PRO-45 och PRO-46 imorgon (6 sep)

2. **Dokumentationsbacklog**
   - 4 dokumentationstasks försenade
   - PRO-30, PRO-31 förfallna 4 sep
   - PRO-32, PRO-33 förfallna 2026-09-05
   - **Åtgärd**: Prioritera PRO-32 och PRO-33 idag

### 🟡 Medelhöga Risker
1. **Integrationstester**
   - PRO-61, PRO-62, PRO-63 förfallna 21 sep
   - Beroende av Epic 3
   - **Åtgärd**: Förbereda testfall nu

2. **Veckorapportering**
   - PRO-34 förfaller imorgon (6 sep)
   - **Status**: Denna rapport genererad automatiskt

### 🟢 Låga Risker
1. **Framework-mappning**
   - PRO-64, PRO-65, PRO-66 förfallna 22 sep
   - Kan göras parallellt

## Plan för Nästa Vecka (6-12 sep)

### Prioritet 1 - Omedelbar
- [ ] PRO-45: Nyckelgenerering UNO Q (Starta 6 sep)
- [ ] PRO-46: Nyckeldistribution via USB (Starta 6 sep)
- [ ] PRO-32: Komponentval dokumentation (Klar 5 sep)
- [ ] PRO-33: Kopplingsdokumentation (Klar 5 sep)

### Prioritet 2 - Veckan
- [ ] PRO-47: Nyckellagring edge node
- [ ] PRO-48: Nyckellagring PAW
- [ ] PRO-49: HMAC-SHA256 edge node
- [ ] PRO-50: HMAC-SHA256 PAW
- [ ] PRO-42: Protokollspecifikation
- [ ] PRO-43: Radio-parametrar

### Prioritet 3 - Om tid
- [ ] PRO-51: Nonce-generering
- [ ] PRO-58-60: Statusvisning
- [ ] PRO-30, PRO-31: Försenade dokumentationstasks

## Resurser

### Automatiserade Mallar
- ✅ Komponentval: docs/templates/komponentval-template.md
- ✅ Kopplingsdokumentation: docs/templates/kopplingsdokumentation-template.md
- ✅ Allmän mall: docs/templates/dokumentmall.md

### GitHub Commits denna vecka
- [50a32bc](https://github.com/Tripl321/yh-lora-auth-projektarbete/commit/50a32bc098d8a51ecc3e2e5520744f550d2827c5) - Komponentval mall
- [a553931](https://github.com/Tripl321/yh-lora-auth-projektarbete/commit/a55393166afcc40add1d89409a1bdec4cff43727) - Kopplingsdokumentation mall
- [5a875e2](https://github.com/Tripl321/yh-lora-auth-projektarbete/commit/5a875e2be2e13358122cb103a3d191c7d8186974) - Allmän mall

## Slutsats

Vecka 1 har varit framgångsrik med alla hårdvaru- och LoRa-tasks klara. Den kritiska vägen är nu Epic 3 (Krypto & Autentisering) som måste startas omedelbart för att hinna till presentationen den 25 september. Dokumentationsbackloggen måste också addresseras för att undvika ytterligare förseningar.

**Nästa steg**: Starta Epic 3 imorgon (6 sep) och slutför PRO-32 och PRO-33 idag.

---
Rapport genererad automatiskt: 2026-09-05
Version: 1.0
