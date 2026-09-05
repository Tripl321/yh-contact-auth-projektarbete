# Automatiserad Veckorapportering - SHALLOT

## Översikt

Veckorapporter för SHALLOT-projektet genereras automatiskt varje fredag klockan 16:00 via Vibe Work.

## Automatiserade Processer

### 1. Veckorapporter (PRO-34, PRO-44, PRO-56, PRO-72)
- **Frekvens**: Varje fredag
- **Källa**: Linear API
- **Destination**: docs/status/vecka-N-DATE.md
- **Innehåll**: 
  - Avslutade tasks
  - Pågående tasks
  - Planerade tasks
  - Blockers och risker
  - Framstegsmetriker

### 2. Dokumentationsmallar
- **Mallar skapade**: 
  - docs/templates/komponentval-template.md (PRO-32)
  - docs/templates/kopplingsdokumentation-template.md (PRO-33)
- **Funktion**: Automatisk fyllning av standardfält (datum, författare, version)
- **Användning**: Kopiera mall till rätt dokument-ID

### 3. Statusuppdateringar
- **Automatisk**: PRO-32 och PRO-33 uppdaterade till "In Progress" idag
- **Manuell**: Andra tasks kräver manuell uppdatering

---

## Manuell Generering

### Generera Veckorapport
För att generera en rapport manuellt, begär från Vibe:

> "Generera veckorapport för vecka X"

Eller:
> "Skapa statusuppdatering för perioden YYYY-MM-DD till YYYY-MM-DD"

### Använda Dokumentationsmallar
1. Navigera till: docs/templates/
2. Kopiera relevant mall (t.ex., komponentval-template.md)
3. Namnge till: docs/03-komponentval.md
4. Fyll i specifika detaljer
5. Committa ändringar

---

## Schemaläggning

### Aktiva Automatiseringar
| Task | Frekvens | Nästa Körning | Status |
|------|----------|---------------|--------|
| Veckorapport Vecka 1 | En gång | 5 Sep 2026 | Klar |
| Veckorapport Vecka 2 | Varje fredag | 12 Sep 2026 | Schemalagd |
| Veckorapport Vecka 3 | Varje fredag | 19 Sep 2026 | Schemalagd |
| Veckorapport Vecka 4 | Varje fredag | 26 Sep 2026 | Schemalagd |

### Kommande Milstolpar
| Milstolpe | Datum | Automatiserad Åtgärd |
|-----------|-------|----------------------|
| PRO-44 | 13 Sep | Generera veckorapport |
| PRO-56 | 20 Sep | Generera veckorapport |
| PRO-72 | 25 Sep | Generera veckorapport |

---

## Konfiguration

### Linear Integration
- **Projekt**: SHALLOT (PRO-)
- **Team**: Projektarbetet
- **API**: Konfigurerad och aktiv

### GitHub Integration
- **Repo**: Tripl321/yh-lora-auth-projektarbete
- **Branch**: main
- **API**: Konfigurerad och aktiv

---

## Felsökning

### Vanliga Problem och Lösningar

#### 1. Tasks saknas i rapporten
- **Orsak**: Task saknar förfallodatum eller projekt
- **Lösning**: Uppdatera task i Linear med förfallodatum och projekt SHALLOT

#### 2. Fel status i rapporten
- **Orsak**: Statusnamn matchar inte förväntade värden
- **Lösning**: Använd standardstatus: Backlog, Todo, In Progress, In Review, Done

#### 3. Dokumentationsmall saknas
- **Orsak**: Mall ej skapad
- **Lösning**: Begär från Vibe: "Skapa mall för [dokumenttyp]"

---

## Underhåll

### Uppdatera Mallar
1. Redigera mall-fil i docs/templates/
2. Testa med ny task
3. Begär uppdatering från Vibe

### Lägg till Ny Automatisering
1. Definiera krav
2. Begär implementation från Vibe
3. Testa och verifiera

---

## Support

För support och frågor:
- **Projektledare**: Johannes Olerås
- **Automatisering**: Vibe Work (Mistral)
- **Dokumentation**: docs/automation/

---

## Historik

| Datum | Åtgärd | Utförande |
|-------|--------|-----------|
| 2026-09-05 | Skapade PRO-32 & PRO-33 mallar | Vibe |
| 2026-09-05 | Genererade Vecka 1 rapport | Vibe |
| 2026-09-05 | Uppdaterade status till In Progress | Vibe |
| 2026-09-04 | Konfigurerade Linear MCP | Johannes |
| 2026-09-01 | Skapade dokumentationsstruktur | Johannes |

---

## Framtida Förbättringar

### Planerade Automatiseringar
1. **GitHub Actions CI/CD** - Automatisk bygg och test
2. **Pull Request Templates** - Standardiserade PR-beskrivningar
3. **Issue Templates** - Standardiserade issue-beskrivningar
4. **Automatiska Påminnelser** - För förfallodagar
5. **Dokumentationsvalidering** - Automatisk kontroll av dokument

### Prioriteringsordning
1. GitHub Actions (Hög prioritet)
2. Pull Request Templates (Medel)
3. Issue Templates (Medel)
4. Påminnelser (Låg)
5. Dokumentationsvalidering (Låg)

---

## Licens

MIT License - Fritt att använda och modifiera för SHALLOT-projektet