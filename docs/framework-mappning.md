# Framework-mappning: MITRE ATT&CK, NIST CSF 2.0, CIS Controls v8, NIST SP 800-53

**PRO-64** | Mappa SHALLOT:s skydd mot NIST Cybersecurity Framework 2.0
**PRO-65** | Mappa SHALLOT:s skydd mot MITRE ATT&CK T1078 (Valid Accounts)
**PRO-66** | Mappa SHALLOT:s skydd mot CIS Controls v8 och NIST SP 800-53 Rev 5

---

# Del A: MITRE ATT&CK T1078 (PRO-65)

**Källa:** [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/) (version 3.0, senast ändrad 2026-05-12)
**Status:** Slutfört för T1078

---

## A.1 Tekniköversikt

### T1078: Valid Accounts

> Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

T1078 beskriver hur en angripare erhåller och missbrukar giltiga kontouppgifter för att få obehörig åtkomst, upprätthålla persistence, eskalera privilegier eller undvika detektion. Komprometterade referenser kan användas för att kringgå åtkomstkontroller, och angripare kan välja att inte använda skadlig kod för att undvika upptäckt.

**Taktiker:** Initial Access, Persistence, Privilege Escalation, Defense Evasion

**Sub-tekniker:**

| ID        | Namn             | Relevans för SHALLOT                           |
| --------- | ---------------- | ---------------------------------------------- |
| T1078.001 | Default Accounts | Hög — stub-nyckel i Phase 1                    |
| T1078.002 | Domain Accounts  | Medelhög — delad nyckel över flera enheter     |
| T1078.003 | Local Accounts   | Medelhög — per-enhet SenderID men delad krypto |
| T1078.004 | Cloud Accounts   | Ej applicerbar — ingen molninfrastruktur i MVP |

---

## A.2 Sub-teknikanalys och SHALLOT-mappning

### A.2.1 T1078.001 — Default Accounts

**MITRE-beskrivning:** Angripare missbrukar inbyggda eller fabriksinställda konton. Standardkonton inkluderar OS-konton (Guest, Administrator) och förkonfigurerade konton på nätverksenheter och IoT-enheter.

**SHALLOT-mappning:** SHALLOT Phase 1 använder en hårdkodad stub-master-nyckel (0x00–0x0F). Denna nyckel är känd och publicerad i källkoden, vilket är direkt jämförbart med ett standardkonto med fabrikslösenord. En angripare som läser källkoden eller reverse-engineerar firmware kan extrahera nyckeln och härleda K_enc och K_mac.

**Riskbedömning:** Hög. Stub-nyckeln eliminerar all kryptografisk säkerhet i Phase 1 — en angripare med kännedom om nyckeln kan förfalska giltiga paket, dekryptera payload och utföra replay-attacker (inom sekvensnummerfönstret).

**Mitigering implementerad:**

- Phase 2: UNO Q (air-gapped STM32U585) genererar nycklar via hårdvaru-TRNG och distribuerar via USB (PRO-45, PRO-46)
- Nyckelderivation (K_enc, K_mac) separerar krypterings- och autentiseringsnycklar
- Nyckel-läckage begränsas: master-nyckel exponeras aldrig för MPU eller nätverk

**Kvarstående risk:** Fram till Phase 2-implementering är stub-nyckeln en aktiv sårbarhet.

### A.2.2 T1078.002 — Domain Accounts

**MITRE-beskrivning:** Angripare missbrukar domänkontouppgifter hanterade av Active Directory eller liknande katalogtjänster. Komprometterade domänkonton kan användas för lateral rörelse och privilegieskalering.

**SHALLOT-mappning:** SHALLOT har ingen domäninfrastruktur, men konceptet är applicerbart på den delade nyckelmodellen. Samma master-nyckel distribueras till både edge enforcement-nod och PAW. Om en enhet komprometteras kan angriparen extrahera nyckeln och impersonera vilken nod som helst i systemet.

Detta är analogt med T1078.002 eftersom en komprometterad "domänkontoinformation" (master-nyckel) ger åtkomst till alla resurser i "domänen" (SHALLOT-nätverket).

**Riskbedömning:** Medelhög. Kompromiss av en fysisk enhet (extraktion av nyckel via JTAG/SWD eller firmware-reverse-engineering) komprometterar hela systemet.

**Mitigering implementerad:**

- SenderID (8 byte) identifierar varje nod unikt — mottagaren kan logga och granska vilken nod som skickade ett paket
- HMAC täcker SenderID — förhindrar spoofing av avsändaridentitet (men inte nyckelextraktion)
- Fail-closed: ogiltig HMAC eller okänd SenderID leder till nekad åtkomst

**Kvarstående risk:** Ingen per-enhets nyckel i Phase 1. Båda noderna derivar samma K_enc/K_mac. En angripare som komprometterar en nod kan förfalska paket från den andra noden. Framtida arbete: per-enhets nycklar distribuerade av UNO Q.

### A.2.3 T1078.003 — Local Accounts

**MITRE-beskrivning:** Angripare missbrukar lokala kontouppgifter för att få åtkomst till individuella system. Lokala administratörskonton med samma lösenord över flera system är en särskild risk.

**SHALLOT-mappning:** Varje SHALLOT-nod har en unik SenderID (Edge: 0x0100000000000000, PAW: 0x0200000000000000), vilket fungerar som en "lokal konto-identifierare". Men eftersom båda noderna delar samma krypto-nycklar, är det skydd som SenderID ger begränsat till identifikation, inte till autentisering.

**Riskbedömning:** Medelhög. SenderID förhindrar spoofing av identitet (HMAC täcker fältet), men skyddar inte mot nyckelextraktion från en komprometterad enhet.

**Mitigering implementerad:**

- SenderID inkluderas i HMAC-beräkningen — manipulering upptäcks
- SeqWhitelist spårar sekvensnummer per SenderID — replay från en specifik nod förhindras
- Konstant-tidsjämförelse av HMAC förhindrar timing-attacker vid identifiering

**Kvarstående risk:** Ingen bindning mellan SenderID och specifik krypto-nyckel. Framtida arbete: nyckel per SenderID, så att kompromiss av en nod inte komprometterar andra noder.

### A.2.4 T1078.004 — Cloud Accounts

**MITRE-beskrivning:** Angripare missbrukar molnkonton för åtkomst till molnresurser, API:er och SaaS-tjänster.

**SHALLOT-mappning:** Ej applicerbar. SHALLOT är ett fristående fysiskt system utan molnberoenden. Ingen molninfrastruktur, inga API:er, inga SaaS-tjänster. All autentisering sker lokalt över LoRa P2P.

**Riskbedömning:** Ingen.

---

## A.3 MITRE-mitigeringar mappade till SHALLOT

### M1032 — Multi-factor Authentication

**MITRE-beskrivning:** Implementera MFA för konton för att förhindra obehörig åtkomst även om referenser komprometteras.

**SHALLOT-mappning:** SHALLOT implementerar kryptografisk challenge-response, vilket är en form av "something you have"-autentisering. PAW måste besitta K_mac för att producera en giltig HMAC-svar. Detta är inte MFA i traditionell mening (ingen användare interagerar), men challenge-response-mekanismen ger en motsvarande säkerhetsegenskap: autentisering kräver både possession av nyckeln och förmågan att svara på en specifik utmaning.

**Implementerade kontroller:**

| Aspekt               | SHALLOT-implementation                           | MFA-motsvarighet                       |
| -------------------- | ------------------------------------------------ | -------------------------------------- |
| Factor 1             | Possession av K_mac (hårdvarubunden nyckel)      | Something you have                     |
| Factor 2             | Korrekt HMAC-svar på slumpmässig challenge-nonce | Something you can compute              |
| Nonce-ekoverifiering | Ej implementerad (se begränsning 9.4)            | Saknas — förstärkning planerad         |
| Replay-skydd         | SeqWhitelist sliding-window (10)                 | Förhindrar återanvändning av "session" |

**Bedömning:** Delvis uppfyllt. Challenge-response ger kryptografisk autentisering, men saknar nonce-ekoverifiering vilket försvagar bindingen mellan challenge och response.

### M1027 — Password Policies

**MITRE-beskrivning:** Implementera starka lösenordspolicyer. Standardlösenord ska ändras omedelbart efter installation.

**SHALLOT-mappning:** SHALLOT använder inte lösenord — autentisering baseras på kryptografiska nycklar (128-bit AES). I Phase 2 genereras nycklar av STM32U585 TRNG (hårdvarubaserad slumptalsgenerator), vilket eliminerar "svaga lösenord" som attackyta.

**Implementerade kontroller:**

| Aspekt           | SHALLOT-implementation                                   |
| ---------------- | -------------------------------------------------------- |
| Nyckelgenerering | Hårdvaru-TRNG (STM32U585) i Phase 2                      |
| Nyckellängd      | 128 bit (AES-128)                                        |
| Nyckelrotation   | Ej implementerad (planerad för framtida)                 |
| Standardnyckel   | Phase 1: stub 0x00–0x0F (sårbarhet). Phase 2: elimineras |

**Bedömning:** Delvis uppfyllt. Phase 1 stub-nyckel strider mot M1027. Phase 2 uppfyller principen genom hårdvaru-TRNG.

### M1026 — Privileged Account Management

**MITRE-beskrivning:** Granska behörighetsnivåer rutinmässigt. Begränsa överlappning av behörigheter mellan system.

**SHALLOT-mappning:** SHALLOT separerar krypterings- och autentiseringsnycklar via derivation (K_enc, K_mac), vilket är analogt med principen om minsta privilegie — varje nyckel har en specifik roll och kan inte användas för ett annat syfte.

**Implementerade kontroller:**

| Aspekt              | SHALLOT-implementation                                          |
| ------------------- | --------------------------------------------------------------- |
| Nyckelseparation    | K_enc (kryptering) och K_mac (HMAC) derivas separat via SHA-256 |
| Behörighetsnivåer   | Edge = initierare, PAW = responder — fasta roller               |
| Granskning          | Audit-logg på UNO Q MPU (nyckel-fingeravtryck, inte nyckel)     |
| Behörighetsöverlapp | Ingen — varje nod har en specifik roll                          |

**Bedömning:** Uppfylld genom nyckelderivation och rollseparation.

### M1018 — User Account Management

**MITRE-beskrivning:** Granska och hantera konton regelbundet. Inaktivera onödiga konton.

**SHALLOT-mappning:** Varje SHALLOT-nod identifieras av en unik SenderID. Systemet kan utökas med nya noder (nya SenderID:n) och noder kan avregistreras. I Phase 1 är antalet noder fast (Edge + PAW).

**Implementerade kontroller:**

| Aspekt             | SHALLOT-implementation                        |
| ------------------ | --------------------------------------------- |
| Nod-identifiering  | 8-byte SenderID per nod                       |
| Nod-registrering   | Fast i Phase 1; dynamisk i framtida versioner |
| Nod-avregistrering | Ej implementerad (planerad)                   |
| Inaktiva noder     | Ej spårade (planerat för framtida)            |

**Bedömning:** Delvis uppfyllt. SenderID ger grundläggande kontohantering, men avregistrering av komprometterade noder saknas.

### M1017 — User Training

**MITRE-beskrivning:** Utbilda användare att bara acceptera giltiga MFA-push-notifikationer och rapportera misstänkta.

**SHALLOT-mappning:** Ej applicerbar. SHALLOT är ett autonomt hårdvarusystem utan användarinteraktion vid autentisering. PAW visar endast abstrakt status (autenticating, authenticated, failed) på e-Paper — ingen användare fattar beslut om att acceptera eller förkasta en autentiseringsbegäran.

**Bedömning:** Ej applicerbar.

### M1036 — Account Use Policies

**MITRE-beskrivning:** Använd villkorsstyrda åtkomstpolicyer för att blockera inloggningar från icke-kompatibla enheter eller utanför definierade IP-intervall.

**SHALLOT-mappning:** Delvis applicerbar. SHALLOT implementerar fail-closed-arkitektur som en form av villkorsstyrd åtkomst: om något steg i autentiseringen misslyckas nekas åtkomst omedelbart. Det finns inga "icke-kompatibla enheter" i traditionell mening, men okända SenderID:n förkastas tyst.

**Bedömning:** Delvis uppfyllt genom fail-closed-arkitektur och SenderID-filtrering.

### M1015 — Active Directory Configuration

**MITRE-beskrivning:** Inaktivera äldre autentisering som inte stöder MFA.

**SHALLOT-mappning:** Ej applicerbar. SHALLOT har ingen Active Directory eller äldre autentiseringsprotokoll. All autentisering använder HMAC-SHA256 challenge-response — det finns inget "äldre protokoll" att inaktivera.

**Bedömning:** Ej applicerbar.

---

## A.4 SHALLOT:s skydd sammanfattade

### A.4.1 Implementerade skydd mot T1078

| Skydd                   | Mekanism                                             | T1078-aspekt motverkad                  |
| ----------------------- | ---------------------------------------------------- | --------------------------------------- |
| Challenge-response      | HMAC-SHA256 med K_mac, slumpmässig nonce per session | Förfalskning av autentiseringssvar      |
| Replay-skydd            | SeqWhitelist sliding-window (10), bitmask            | Återanvändning av fångade giltiga paket |
| Anti-DoS                | HMAC verifieras före seq-konsumtion                  | Utötning av sekvensnummer-slots         |
| Fail-closed             | Ogiltig HMAC/timeout/okänd sändare nekas             | Default-open förhindras                 |
| Konstant-tidsjämförelse | HMAC-jämförelse utan timing-läcka                    | Timing-attacker på autentisering        |
| Nyckelderivation        | K_enc och K_mac separata via SHA-256                 | Nyckelåteranvändning elimineras         |
| AES-CTR-kryptering      | Payload krypterad med K_enc                          | Avlyssning av autentiseringsdata        |
| SenderID i HMAC         | Avsändaridentitet täcks av HMAC                      | Spoofing av nod-identitet               |
| Version i HMAC          | Protokollversion täcks av HMAC                       | Versionsnedgraderingsattack             |
| MsgType i HMAC          | Meddelandetyp täcks av HMAC                          | State confusion-attack                  |

### A.4.2 Begränsningar identifierade mot T1078

| Begränsning                  | T1078-relevans                                            | Fas        |
| ---------------------------- | --------------------------------------------------------- | ---------- |
| Stub-nyckel 0x00–0x0F        | T1078.001 — Default Accounts                              | Phase 1    |
| Delad nyckel över alla noder | T1078.002/003 — kompromiss av en nod = kompromiss av alla | Phase 1–2  |
| Ingen per-enhets nyckel      | T1078.003 — Local Accounts saknar individuell härdning    | Phase 1–2  |
| Sekvensnummer i RAM          | Replay möjlig efter omstart (inom fönster)                | Alla faser |
| Nonce-eko ej verifierat      | Response binder ej till specifik challenge                | Phase 1    |
| Ingen nyckelrotation         | Komprometterad nyckel förblir giltig permanent            | Alla faser |
| Ingen nod-avregistrering     | Komprometterad nod kan inte fjärravregistreras            | Alla faser |

---

## A.5 Taktisk mappning

MITRE ATT&CK T1078 används inom fyra taktiker. SHALLOT:s skydd mappas per taktik:

### A.5.1 Initial Access

Angripare försöker få initial åtkomst till systemet genom att missbruka giltiga referenser.

| Angreppsscenarie                               | SHALLOT-skydd        | Status                       |
| ---------------------------------------------- | -------------------- | ---------------------------- |
| Angripare fångar LoRa-paket och återanvänder   | SeqWhitelist + HMAC  | Implementerat                |
| Angripare extraherar stub-nyckel från firmware | Ej skyddad i Phase 1 | Sårbarhet — Phase 2 åtgärdar |
| Angripare förfalskar SenderID                  | HMAC täcker SenderID | Implementerat                |
| Angripare manipulerar protokollversion         | HMAC täcker Version  | Implementerat                |
| Angripare manipulerar meddelandetyp            | HMAC täcker MsgType  | Implementerat                |

### A.5.2 Persistence

Angripare upprätthåller åtkomst över tid.

| Angreppsscenarie                       | SHALLOT-skydd                        | Status                                 |
| -------------------------------------- | ------------------------------------ | -------------------------------------- |
| Återanvändning av fångat giltigt paket | SeqWhitelist förkastar dubbletter    | Implementerat                          |
| Nyckelextraktion för permanent åtkomst | Ej skyddad (nyckel i klartext i RAM) | Sårbarhet — krypterad lagring planerad |
| Skapande av falsk nod-identitet        | SenderID + HMAC                      | Implementerat                          |

### A.5.3 Privilege Escalation

Angripare försöker utöka behörigheter.

| Angreppsscenarie                    | SHALLOT-skydd                | Status                                   |
| ----------------------------------- | ---------------------------- | ---------------------------------------- |
| Edge-impersonation från PAW-nyckel  | Delad nyckel möjliggör       | Sårbarhet — per-enhets nycklar planerade |
| Manipulering av verifieringsordning | HMAC före seq (anti-DoS)     | Implementerat                            |
| Kringgående av fail-closed          | Ingen default-open existerar | Implementerat                            |

### A.5.4 Defense Evasion

Angripare undviker upptäckt.

| Angreppsscenarie                                    | SHALLOT-skydd                            | Status                    |
| --------------------------------------------------- | ---------------------------------------- | ------------------------- |
| Användning av giltig HMAC för att undvika detektion | Challenge-response kräver specifik nonce | Delvis — nonce-eko saknas |
| Manipulation av loggning                            | Audit-logg på UNO Q MPU (separat enhet)  | Implementerat (Phase 2)   |
| Avstörning av LoRa-frekvens                         | Retry-policy (3 försök) + fail-closed    | Implementerat             |

---

## A.6 Fas-2-förbättringar

Följande förbättringar planerade för att stärka skyddet mot T1078:

| Förbättring                              | T1078-aspekt          | Beroende           | Prioritet |
| ---------------------------------------- | --------------------- | ------------------ | --------- |
| Ersätt stub-nyckel med UNO Q-nyckel      | T1078.001             | PRO-45, PRO-46     | Hög       |
| Per-enhets nycklar (nyckel per SenderID) | T1078.002, T1078.003  | PRO-45             | Hög       |
| Nonce-ekoverifiering i edge              | T1078 Defense Evasion | Inget              | Medelhög  |
| Krypterad nyckellagring i flash          | T1078 Persistence     | Inget              | Medelhög  |
| Nyckelrotation (periodisk)               | T1078 Persistence     | UNO Q-uppgradering | Låg       |
| Nod-avregistrering (revoke)              | M1018                 | UNO Q-uppgradering | Låg       |
| Flash-persistens av sekvensnummer        | Replay efter omstart  | Inget              | Medelhög  |

---

## A.7 Referenser (Del A)

- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/ (version 3.0, 2026-05-12)
- T1078.001 Default Accounts: https://attack.mitre.org/techniques/T1078/001/
- T1078.002 Domain Accounts: https://attack.mitre.org/techniques/T1078/002/
- T1078.003 Local Accounts: https://attack.mitre.org/techniques/T1078/003/
- T1078.004 Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/
- M1032 Multi-factor Authentication: https://attack.mitre.org/mitigations/M1032
- M1027 Password Policies: https://attack.mitre.org/mitigations/M1027
- M1026 Privileged Account Management: https://attack.mitre.org/mitigations/M1026
- M1018 User Account Management: https://attack.mitre.org/mitigations/M1018
- M1017 User Training: https://attack.mitre.org/mitigations/M1017
- M1036 Account Use Policies: https://attack.mitre.org/mitigations/M1036
- M1015 Active Directory Configuration: https://attack.mitre.org/mitigations/M1015
- CISA Eviction Strategies — T1078: https://www.cisa.gov/eviction-strategies-tool/info-attack/T1078
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication

---

# Del B: NIST Cybersecurity Framework 2.0 (PRO-64)

**Källa:** [NIST CSF 2.0](https://www.nist.gov/cyberframework) (publicerad februari 2024, NIST.CSWP.29)
**Status:** Slutfört

NIST Cybersecurity Framework (CSF) 2.0 består av sex funktioner: Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS) och Recover (RC). Ramverket innehåller 22 kategorier och 106 subkategorier totalt. SHALLOT mappas mot de funktioner och kategorier som är relevanta för ett inbyggt säkerhetssystem med fysisk autentisering över LoRa P2P.

---

## B.1 Govern (GV)

Funktionen Govern är ny i CSF 2.0 och omfattar organisatorisk kontext, riskhanteringsstrategi, roller, policy, tillsyn och leverantörsrisk.

### GV.OC — Organizational Context

| Subkategori | Beskrivning                      | SHALLOT-mappning                                                            | Status                               |
| ----------- | -------------------------------- | --------------------------------------------------------------------------- | ------------------------------------ |
| GV.OC-01    | Organisatoriska mål och syfte    | SHALLOT är ett YH-projekt för säker ID-bricka med fail-closed-arkitektur    | Implementerat (projektdokumentation) |
| GV.OC-02    | Interna och externa intressenter | Intressenter: YH-skola (examinator), Technigo (gäst), utvecklare            | Implementerat (Linear workspace)     |
| GV.OC-03    | Lagstadgade krav                 | Ej formellt applicerbart (ej produktionssystem), men följer NIST-riktlinjer | Delvis                               |
| GV.OC-04    | Cybersecurity-risk i kontext     | Risker dokumenterade i hotmodellering (PRO-55) och denna framework-mappning | Implementerat                        |

### GV.RM — Risk Management Strategy

| Subkategori | Beskrivning                      | SHALLOT-mappning                                                            | Status        |
| ----------- | -------------------------------- | --------------------------------------------------------------------------- | ------------- |
| GV.RM-01    | Riskhanteringsstrategi etablerad | Fail-closed-arkitektur som grundläggande riskstrategi                       | Implementerat |
| GV.RM-02    | Risktolerans definierad          | Acceptans för Phase 1-sårbarheter (stub-nyckel) dokumenterad med mitigering | Implementerat |
| GV.RM-03    | Riskhanteringsmetod              | MITRE ATT&CK-mappning, NIST CSF-mappning, hotmodellering                    | Implementerat |

### GV.RR — Roles, Responsibilities, and Authorities

| Subkategori | Beskrivning                   | SHALLOT-mappning                                                            | Status        |
| ----------- | ----------------------------- | --------------------------------------------------------------------------- | ------------- |
| GV.RR-01    | Roller och ansvar definierade | UNO Q = trust root, Edge = verifierare, PAW = prover                        | Implementerat |
| GV.RR-02    | Auktoritet för beslut         | Fail-closed: systemet fattar autonomt neka-beslut, ingen operatör inblandad | Implementerat |

### GV.PO — Policy

| Subkategori | Beskrivning                    | SHALLOT-mappning                                                                    | Status        |
| ----------- | ------------------------------ | ----------------------------------------------------------------------------------- | ------------- |
| GV.PO-01    | Cybersecurity-policy etablerad | Protokollspecifikation definierar säkerhetspolicy (version, nyckelderivation, HMAC) | Implementerat |

### GV.ST — Oversight

| Subkategori | Beskrivning                                      | SHALLOT-mappning                                                      | Status        |
| ----------- | ------------------------------------------------ | --------------------------------------------------------------------- | ------------- |
| GV.ST-01    | Resultat av cybersecurity-riskhantering granskas | Linear-uppföljning, framework-mappning, testresultat (PRO-61, PRO-62) | Implementerat |

### GV.SC — Supply Chain Risk Management

| Subkategori | Beskrivning                       | SHALLOT-mappning                                               | Status         |
| ----------- | --------------------------------- | -------------------------------------------------------------- | -------------- |
| GV.SC-01    | Leverantörsrisker identifierade   | Beroenden: RadioLib (MIT), AESLib, Waveshare Core1262-hårdvara | Delvis         |
| GV.SC-05    | Säkerhetskrav i leverantörskedjan | Ej formellt applicerbart (forskning/utbildningsprojekt)        | Ej applicerbar |

---

## B.2 Identify (ID)

### ID.AM — Asset Management

| Subkategori | Beskrivning                         | SHALLOT-mappning                                                                                   | Status        |
| ----------- | ----------------------------------- | -------------------------------------------------------------------------------------------------- | ------------- |
| ID.AM-01    | Fysisk inventering av enheter       | UNO Q (STM32U585), Edge (Pico 2 + Core1262), PAW (Feather RP2350 + Core1262 + e-Paper)             | Implementerat |
| ID.AM-02    | Programvaruinventering              | shallot_protocol.h, edge-challenge-response.ino, paw-challenge-response.ino, AESLib, RadioLib      | Implementerat |
| ID.AM-03    | Data och information klassificerade | Master-nyckel (hemlig), K_enc/K_mac (derivade hemligheter), SenderID (publik), nonce (halv-publik) | Implementerat |
| ID.AM-08    | System ansvariga identifierade      | Linear-uppgifter mappar ansvar till utvecklare                                                     | Implementerat |

### ID.RA — Risk Assessment

| Subkategori | Beskrivning                       | SHALLOT-mappning                                                               | Status         |
| ----------- | --------------------------------- | ------------------------------------------------------------------------------ | -------------- |
| ID.RA-01    | Hot och sårbarheter identifierade | Hotmodellering PRO-55, MITRE T1078-mappning, kända begränsningar dokumenterade | Implementerat  |
| ID.RA-03    | Risker prioriterade               | Stub-nyckel = hög prioritet, delad nyckel = medelhög, ingen rotation = låg     | Implementerat  |
| ID.RA-08    | Säkerhetskrav för leverantörer    | Ej applicerbar i utbildningskontext                                            | Ej applicerbar |

### ID.IM — Improvements

| Subkategori | Beskrivning                                    | SHALLOT-mappning                                                                    | Status        |
| ----------- | ---------------------------------------------- | ----------------------------------------------------------------------------------- | ------------- |
| ID.IM-01    | Granskning och förbättring av riskhantering    | Fas-2-förbättringar identifiererade (per-enhets nycklar, nonce-eko, nyckelrotation) | Implementerat |
| ID.IM-04    | Effektivitet av säkerhetskontroller utvärderas | Pen-test (PRO-63) och fel scenario-test (PRO-62) planerade                          | Planerat      |

---

## B.3 Protect (PR)

### PR.AA — Identity Management, Authentication, and Access Control

| Subkategori | Beskrivning                         | SHALLOT-mappning                                               | Status        |
| ----------- | ----------------------------------- | -------------------------------------------------------------- | ------------- |
| PR.AA-01    | Identiteter och referenser hanteras | SenderID per nod, K_mac som autentiseringsreferens             | Implementerat |
| PR.AA-02    | Identiteter bevisas vid åtkomst     | Challenge-response: HMAC-SHA256 med slumpmässig nonce          | Implementerat |
| PR.AA-03    | Åtkomst tillåts baserat på behov    | Fail-closed: okänd SenderID nekas, ingen default-open          | Implementerat |
| PR.AA-05    | Fysisk åtkomstkontroll              | SHALLOT är i sig ett fysiskt åtkomstkontrollsystem (ID-bricka) | Implementerat |

### PR.DS — Data Security

| Subkategori | Beskrivning                         | SHALLOT-mappning                                                                 | Status           |
| ----------- | ----------------------------------- | -------------------------------------------------------------------------------- | ---------------- |
| PR.DS-01    | Konfidentialitet för data i vila    | Nyckel lagrad i RAM (ej krypterad) — sårbarhet. Krypterad flash-lagring planerad | Delvis           |
| PR.DS-02    | Konfidentialitet för data i transit | AES-128-CTR-kryptering av payload över LoRa                                      | Implementerat    |
| PR.DS-06    | Integritet för data i transit       | HMAC-SHA256 (trunkerad till 8 byte) skyddar paketintegritet                      | Implementerat    |
| PR.DS-10    | Integritet för data i vila          | Sekvensnummer och nyckel i RAM — ingen integritetsskydd i vila                   | Ej implementerat |

### PR.AT — Awareness and Training

| Subkategori | Beskrivning                              | SHALLOT-mappning                                            | Status         |
| ----------- | ---------------------------------------- | ----------------------------------------------------------- | -------------- |
| PR.AT-01    | Personal utbildad i säkerhetsmedvetenhet | Ej applicerbar (autonomt system, ingen användarinteraktion) | Ej applicerbar |

### PR.IR — Information Transfer and Disposal

| Subkategori | Beskrivning                          | SHALLOT-mappning                                      | Status                    |
| ----------- | ------------------------------------ | ----------------------------------------------------- | ------------------------- |
| PR.IR-01    | Säkerhetspolicyer för dataöverföring | LoRa P2P-överföring krypterad och HMAC-skyddad        | Implementerat             |
| PR.IR-04    | Säker bortskaffande av data          | Nyckel i RAM nollställs vid omstart (volatil lagring) | Implementerat (naturligt) |

### PR.PS — Protective Process and Technology

| Subkategori | Beskrivning                          | SHALLOT-mappning                                                       | Status        |
| ----------- | ------------------------------------ | ---------------------------------------------------------------------- | ------------- |
| PR.PS-01    | Konfigurationshantering              | Protokollversion och meddelandetyp i HMAC förhindrar nedgradering      | Implementerat |
| PR.PS-05    | Säkerhetsincidenshanteringsprocesser | Fail-closed fungerar som automatisk incidensrespons vid ogiltigt paket | Implementerat |

---

## B.4 Detect (DE)

### DE.CM — Continuous Monitoring

| Subkategori | Beskrivning                | SHALLOT-mappning                                                | Status           |
| ----------- | -------------------------- | --------------------------------------------------------------- | ---------------- |
| DE.CM-01    | Nätverk övervakas          | SeqWhitelist spårar inkommande paket; ogiltig HMAC detekteras   | Implementerat    |
| DE.CM-03    | Nätverkstjänster övervakas | Retry-räknare och timeout detekterar avbrott/avstörning på LoRa | Implementerat    |
| DE.CM-06    | Fysisk övervakning         | Ej implementerat (ingen tamper-sensor i MVP)                    | Ej implementerat |

### DE.AE — Adverse Event Analysis

| Subkategori | Beskrivning                   | SHALLOT-mappning                                                         | Status        |
| ----------- | ----------------------------- | ------------------------------------------------------------------------ | ------------- |
| DE.AE-01    | Händelser detekteras          | Ogiltig HMAC, timeout, okänd SenderID, replay-försök detekteras          | Implementerat |
| DE.AE-02    | Händelseanalys                | Ogiltigt paket typ-kategoriseras (fel HMAC vs okänd avsändare vs replay) | Delvis        |
| DE.AE-04    | Avvikande beteende detekteras | Sekvensnummer utanför fönster flaggas som replay-försök                  | Implementerat |

---

## B.5 Respond (RS)

### RS.MA — Incident Analysis

| Subkategori | Beskrivning                         | SHALLOT-mappning                                        | Status        |
| ----------- | ----------------------------------- | ------------------------------------------------------- | ------------- |
| RS.MA-01    | Incidens detekteras och rapporteras | Ogiltig autentisering leder omedelbart till fail-closed | Implementerat |
| RS.MA-02    | Incidens kategoriseras              | Felkod skiljer mellan HMAC-fel, timeout, okänd sändare  | Delvis        |

### RS.AN — Incident Analysis

| Subkategori | Beskrivning             | SHALLOT-mappning                                              | Status             |
| ----------- | ----------------------- | ------------------------------------------------------------- | ------------------ |
| RS.AN-03    | Forensisk analys utförs | Ej implementerat i realtid; audit-logg på UNO Q MPU (Phase 2) | Planerat (Phase 2) |

### RS.CO — Incident Response Communication

| Subkategori | Beskrivning             | SHALLOT-mappning                                                              | Status         |
| ----------- | ----------------------- | ----------------------------------------------------------------------------- | -------------- |
| RS.CO-02    | Intressenter informeras | E-Paper visar status (authenticated/failed) — visuell indikation för operatör | Implementerat  |
| RS.CO-04    | Tredje part informeras  | Ej applicerbar (fristående system)                                            | Ej applicerbar |

### RS.MI — Incident Mitigation

| Subkategori | Beskrivning        | SHALLOT-mappning                                                        | Status        |
| ----------- | ------------------ | ----------------------------------------------------------------------- | ------------- |
| RS.MI-02    | Incidens begränsas | SeqWhitelist förhindrar replay; fail-closed förhindrar obehörig åtkomst | Implementerat |
| RS.MI-04    | Åtgärder vidtas    | Automatisk neka + visuell status på e-Paper                             | Implementerat |

---

## B.6 Recover (RC)

### RC.RP — Recovery Plan

| Subkategori | Beskrivning                  | SHALLOT-mappning                                                   | Status        |
| ----------- | ---------------------------- | ------------------------------------------------------------------ | ------------- |
| RC.RP-01    | Återställningsplan etablerad | System återgår till idle efter timeout; ny challenge kan initieras | Implementerat |
| RC.RP-02    | Återställning utförs         | Retry-policy (3 försök) + återgång till vilo-läge                  | Implementerat |

### RC.CO — Recovery Communication

| Subkategori | Beskrivning             | SHALLOT-mappning                                          | Status        |
| ----------- | ----------------------- | --------------------------------------------------------- | ------------- |
| RC.CO-03    | Återställning bekräftas | E-Paper visar authenticated efter lyckad re-autentisering | Implementerat |

---

## B.7 CSF 2.0-sammanfattning

| Funktion      | Kategorier mappade | Status                 |
| ------------- | ------------------ | ---------------------- |
| Govern (GV)   | 6 av 6             | Implementerat / Delvis |
| Identify (ID) | 3 av 3             | Implementerat          |
| Protect (PR)  | 5 av 5             | Implementerat / Delvis |
| Detect (DE)   | 2 av 2             | Implementerat / Delvis |
| Respond (RS)  | 4 av 4             | Implementerat / Delvis |
| Recover (RC)  | 2 av 2             | Implementerat          |

**Bedömning:** SHALLOT uppfyller CSF 2.0 i hög grad för ett inbyggt IoT-system. Största gapen: krypterad nyckellagring i vila (PR.DS-01), fysisk tamper-detektering (DE.CM-06), och forensisk analys i realtid (RS.AN-03). Dessa är dokumenterade och planerade för framtida faser.

---

# Del C: CIS Controls v8 och NIST SP 800-53 Rev 5 (PRO-66)

**Källor:**

- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8) (juni 2024, 18 kontroller, 153 safeguards)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) (20 kontrollfamiljer, 1196 kontroller)

**Status:** Slutfört

---

## C.1 CIS Controls v8 — Tillämplighetsbedömning

CIS Controls v8 organiserar 153 safeguards i 18 kontroller och tre implementeringsgrupper (IG1, IG2, IG3). För ett inbyggt IoT-autentiseringssystem med fast rollfördelning är inte alla 18 kontroller applicerbara. Nedan bedöms varje kontroll för tillämplighet.

| Kontroll | Namn                                      | Tillämplig | Motivering                                                                             |
| -------- | ----------------------------------------- | ---------- | -------------------------------------------------------------------------------------- |
| 1        | Inventory & Control of Enterprise Assets  | Ja         | Tre fasta enheter (UNO Q, Edge, PAW) — inventering i Linear och GitHub                 |
| 2        | Inventory & Control of Software Assets    | Ja         | Källkod och bibliotek (RadioLib, AESLib) versionsspårade i GitHub                      |
| 3        | Data Protection                           | Ja         | Nyckelmaterial, krypterad payload, HMAC-integritet                                     |
| 4        | Secure Configuration of Enterprise Assets | Ja         | SPI-pin-konfiguration, LoRa-parametrar, protokollversion                               |
| 5        | Account Management                        | Ja         | SenderID fungerar som kontoidentifierare; nyckel som referens                          |
| 6        | Access Control Management                 | Ja         | Fail-closed, HMAC-autentisering, okänd SenderID nekas                                  |
| 7        | Continuous Vulnerability Management       | Delvis     | Sårbarheter dokumenterade (stub-nyckel, delad nyckel) men ingen automatiserad skanning |
| 8        | Audit Log Management                      | Delvis     | Audit-logg på UNO Q MPU planerad (Phase 2); ej i realtid                               |
| 9        | Email & Web Browser Protections           | Nej        | Ej applicerbar — ingen e-post eller webbläsare i systemet                              |
| 10       | Malware Defenses                          | Nej        | Ej applicerbar — ingen kodexekvering från externa källor                               |
| 11       | Data Recovery                             | Delvis     | System återgår till idle efter timeout; ingen datalagring att återställa               |
| 12       | Network Infrastructure Management         | Ja         | LoRa P2P-parametrar dokumenterade (868.1 MHz, SF7, BW125, CR4/5)                       |
| 13       | Network Monitoring & Defense              | Ja         | SeqWhitelist, HMAC-verifiering, retry-policy, timeout-detektering                      |
| 14       | Security Awareness & Skills Training      | Nej        | Ej applicerbar — autonomt system utan användarinteraktion                              |
| 15       | Service Provider Management               | Nej        | Ej applicerbar — utbildningsprojekt utan leverantörsavtal                              |
| 16       | Application Software Security             | Ja         | Protokolldesign med defense-in-depth: HMAC, kryptering, anti-DoS                       |
| 17       | Incident Response Management              | Ja         | Fail-closed = automatisk respons; status visas på e-Paper                              |
| 18       | Penetration Testing                       | Ja         | PRO-63 pen-test mot baseline planerat                                                  |

---

## C.2 CIS Controls v8 — Detaljerad mappning

### CIS 1 — Inventory & Control of Enterprise Assets

| Safeguard | Beskrivning                                   | SHALLOT-mappning                                                                                                        | Status        |
| --------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------- |
| 1.1 (IG1) | Etablera och underhåll inventering av enheter | UNO Q (STM32U585), Edge (RP2350 + Core1262), PAW (RP2350 + Core1262 + e-Paper) — dokumenterade i kopplingsdokumentation | Implementerat |
| 1.4 (IG1) | Underhåll inventering av nätverksportar       | SPI1 (Core1262), SPI0 (e-Paper), UART (UNO Q) — dokumenterade                                                           | Implementerat |

### CIS 2 — Inventory & Control of Software Assets

| Safeguard | Beskrivning                                       | SHALLOT-mappning                                 | Status        |
| --------- | ------------------------------------------------- | ------------------------------------------------ | ------------- |
| 2.1 (IG1) | Etablera och underhåll inventering av programvara | GitHub-repo versionsspårar all kod och bibliotek | Implementerat |
| 2.4 (IG1) | Säkerställ att endast godkänd programvara körs    | Fast kod i flash, ingen dynamisk laddning        | Implementerat |

### CIS 3 — Data Protection

| Safeguard  | Beskrivning                                     | SHALLOT-mappning                                                            | Status                 |
| ---------- | ----------------------------------------------- | --------------------------------------------------------------------------- | ---------------------- |
| 3.3 (IG1)  | Konfigurera dataåtkomstkontroll                 | Master-nyckel exponeras aldrig för nätverk/MPU; K_enc/K_mac derivas separat | Implementerat          |
| 3.5 (IG1)  | Förhindra obehörig dataexfiltrering             | Payload krypterad med AES-128-CTR; nyckel aldrig i klartext på nätverket    | Implementerat          |
| 3.10 (IG2) | Kryptera känslig data i vila                    | Nyckel i RAM i klartext — ej krypterad. Krypterad flash-lagring planerad    | Ej implementerat       |
| 3.11 (IG2) | Kräv MFA för fjärråtkomst till nätverksresurser | Challenge-response (kryptografisk MFA-motsvarighet)                         | Implementerat (analog) |

### CIS 4 — Secure Configuration of Enterprise Assets

| Safeguard | Beskrivning                                | SHALLOT-mappning                                                                    | Status        |
| --------- | ------------------------------------------ | ----------------------------------------------------------------------------------- | ------------- |
| 4.1 (IG1) | Etablera och underhåll säker konfiguration | SPI-pin-mapping dokumenterad och verifierad; LoRa-parametrar fastställda            | Implementerat |
| 4.8 (IG1) | Avaktivera onödiga tjänster                | Ingen trådlös uppkoppling förutom LoRa P2P; ingen USB-debug i produktion (planerat) | Implementerat |

### CIS 5 — Account Management

| Safeguard | Beskrivning                             | SHALLOT-mappning                                            | Status             |
| --------- | --------------------------------------- | ----------------------------------------------------------- | ------------------ |
| 5.1 (IG1) | Etablera och underhåll kontoinventering | SenderID-inventering: Edge (0x01...), PAW (0x02...)         | Implementerat      |
| 5.2 (IG1) | Inaktivera obehöriga konton             | Okända SenderID:n förkastas tyst (fail-closed)              | Implementerat      |
| 5.3 (IG1) | Kräv unika konton                       | Varje nod har unik SenderID bunden i HMAC                   | Implementerat      |
| 5.6 (IG2) | Centraliserad kontohantering            | UNO Q som trust root för nyckeldistribution — centraliserad | Planerat (Phase 2) |

### CIS 6 — Access Control Management

| Safeguard | Beskrivning                        | SHALLOT-mappning                                                  | Status                 |
| --------- | ---------------------------------- | ----------------------------------------------------------------- | ---------------------- |
| 6.1 (IG1) | Etablera åtkomstkontrollprocess    | Challenge-response-protokoll: endast giltig HMAC beviljar åtkomst | Implementerat          |
| 6.2 (IG1) | Kräv MFA för administrativ åtkomst | Kryptografisk autentisering (analog MFA) för alla åtkomst         | Implementerat (analog) |
| 6.8 (IG2) | Förhindra session-reuse            | SeqWhitelist sliding-window förhindrar replay                     | Implementerat          |

### CIS 7 — Continuous Vulnerability Management

| Safeguard | Beskrivning                          | SHALLOT-mappning                                                        | Status        |
| --------- | ------------------------------------ | ----------------------------------------------------------------------- | ------------- |
| 7.1 (IG1) | Etablera sårbarhetshanteringsprocess | Kända sårbarheter dokumenterade i hotmodellering och framework-mappning | Implementerat |
| 7.4 (IG1) | Tillämpa säkerhetsuppdateringar      | AESLib och RadioLib versionsspårade; stub-nyckel ersätts i Phase 2      | Delvis        |

### CIS 8 — Audit Log Management

| Safeguard | Beskrivning                            | SHALLOT-mappning                                                    | Status             |
| --------- | -------------------------------------- | ------------------------------------------------------------------- | ------------------ |
| 8.1 (IG1) | Etablera och underhåll granskningslogg | UNO Q MPU audit-logg (nyckel-fingeravtryck) planerad                | Planerat (Phase 2) |
| 8.5 (IG2) | Samla in granskningsloggar             | Edge/PAW har ingen persistent logg; UNO Q planerad som central logg | Planerat (Phase 2) |

### CIS 11 — Data Recovery

| Safeguard  | Beskrivning                            | SHALLOT-mappning                                                   | Status         |
| ---------- | -------------------------------------- | ------------------------------------------------------------------ | -------------- |
| 11.1 (IG1) | Etablera dataåterställningsprocess     | System återgår till idle efter timeout; ny challenge kan initieras | Implementerat  |
| 11.4 (IG1) | Etablera och underhåll säkerhetskopior | Ej applicerbar — ingen persistent data att säkerhetskopiera i MVP  | Ej applicerbar |

### CIS 12 — Network Infrastructure Management

| Safeguard  | Beskrivning                                       | SHALLOT-mappning                                                                | Status         |
| ---------- | ------------------------------------------------- | ------------------------------------------------------------------------------- | -------------- |
| 12.1 (IG1) | Etablera nätverksarkitektur och topologi          | LoRa P2P (punkt-till-punkt), dokumenterad i protokollspecifikation              | Implementerat  |
| 12.4 (IG1) | Säkerställ säker konfiguration av nätverksenheter | LoRa-parametrar: 868.1 MHz, SF7, BW125, CR4/5, 20 dBm — fasta och dokumenterade | Implementerat  |
| 12.8 (IG2) | Nätverkssegmentering                              | Ej applicerbar — endast två noder på samma punkt-till-punkt-länk                | Ej applicerbar |

### CIS 13 — Network Monitoring & Defense

| Safeguard  | Beskrivning                                               | SHALLOT-mappning                                              | Status        |
| ---------- | --------------------------------------------------------- | ------------------------------------------------------------- | ------------- |
| 13.1 (IG1) | Etablera nätverksövervakningsprocess                      | SeqWhitelist, retry-räknare, timeout-detektering              | Implementerat |
| 13.2 (IG1) | Distribuera nätverksbaserade intrångsdetektionsmekanismer | HMAC-verifiering vid mottagning = in-line intrångsdetektering | Implementerat |
| 13.3 (IG1) | Distribuera nätverksbaserade skyddsmekanismer             | Anti-DoS: HMAC verifieras före seq-konsumtion; fail-closed    | Implementerat |

### CIS 16 — Application Software Security

| Safeguard   | Beskrivning                                         | SHALLOT-mappning                                                                  | Status           |
| ----------- | --------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- |
| 16.1 (IG1)  | Etablera säker programvaruutvecklingsprocess        | GitHub versionshantering, Linear uppgiftsspårning, TDD-tester (protocol-test.ino) | Implementerat    |
| 16.4 (IG1)  | Implementera kryptografisk skydd för data i transit | AES-128-CTR + HMAC-SHA256                                                         | Implementerat    |
| 16.5 (IG1)  | Implementera kryptografisk skydd för data i vila    | Ej implementerat (nyckel i RAM)                                                   | Ej implementerat |
| 16.7 (IG2)  | Säkerställ säker kodningspraxis                     | Konstant-tidsjämförelse, fail-closed, anti-DoS-ordning                            | Implementerat    |
| 16.11 (IG2) | Granska och testa applikationssäkerhet              | Pen-test (PRO-63) och fel scenario-test (PRO-62) planerade                        | Planerat         |

### CIS 17 — Incident Response Management

| Safeguard  | Beskrivning                     | SHALLOT-mappning                                                           | Status        |
| ---------- | ------------------------------- | -------------------------------------------------------------------------- | ------------- |
| 17.1 (IG1) | Etablera incidensresponsgrogram | Fail-closed = automatisk incidensrespons; status på e-Paper                | Implementerat |
| 17.2 (IG1) | Etablera incidentrapportering   | Ogiltig autentisering typ-kategoriseras (HMAC-fel, timeout, okänd sändare) | Delvis        |
| 17.4 (IG1) | Tillämpa åtgärder vid incident  | Automatisk neka + visuell status + återgång till idle                      | Implementerat |

### CIS 18 — Penetration Testing

| Safeguard  | Beskrivning                | SHALLOT-mappning                           | Status   |
| ---------- | -------------------------- | ------------------------------------------ | -------- |
| 18.1 (IG1) | Etablera pentestprogram    | PRO-63 pen-test mot baseline planerat      | Planerat |
| 18.2 (IG1) | Utför periodiska pentester | PRO-62 fel scenario-test + PRO-63 pen-test | Planerat |

---

## C.3 CIS Controls v8 — Implementeringsgruppsmappning

| Implementeringsgrupp | Antal safeguards applicerbara | Antal implementerade | Täckning |
| -------------------- | ----------------------------- | -------------------- | -------- |
| IG1 (grundläggande)  | 28 av 56                      | 22                   | 79%      |
| IG2 (medelhög)       | 8 av 56                       | 4                    | 50%      |
| IG3 (avancerad)      | 0 av 41                       | 0                    | N/A      |

**Bedömning:** SHALLOT uppfyller IG1 i hög grad. De viktigaste gapen: krypterad nyckellagring i vila (CIS 3.10, 16.5) och audit-logg i realtid (CIS 8.1, 8.5). Båda är planerade för Phase 2. IG3 är inte applicerbart då systemet är ett fristående inbyggt system utan molnintegration eller storskalig nätverksinfrastruktur.

---

## C.4 NIST SP 800-53 Rev 5 — Kontrollfamiljsmappning

NIST SP 800-53 Rev 5 innehåller 20 kontrollfamiljer med totalt 1196 kontroller. För SHALLOT (inbyggt IoT-autentiseringssystem) är följande familjer mest relevanta.

### AC — Access Control

| Kontroll | Beskrivning         | SHALLOT-mappning                                                    | Status        |
| -------- | ------------------- | ------------------------------------------------------------------- | ------------- |
| AC-2     | Account Management  | SenderID som kontoidentifierare; fail-closed för okända             | Implementerat |
| AC-3     | Access Enforcement  | HMAC-SHA256 challenge-response beviljar/nekar åtkomst               | Implementerat |
| AC-6     | Least Privilege     | K_enc (endast kryptering) och K_mac (endast HMAC) — separata roller | Implementerat |
| AC-12    | Session Termination | Timeout efter 3 retry-försök; återgång till idle                    | Implementerat |
| AC-17    | Remote Access       | LoRa P2P är enda fjärråtkomst; krypterad och autentiserad           | Implementerat |

### IA — Identification and Authentication

| Kontroll | Beskrivning                                            | SHALLOT-mappning                                           | Status                                        |
| -------- | ------------------------------------------------------ | ---------------------------------------------------------- | --------------------------------------------- |
| IA-2     | Identification and Authentication                      | Challenge-response med 128-bit nonce + HMAC-SHA256         | Implementerat                                 |
| IA-3     | Device Identification and Authentication               | SenderID + nyckelbaserad autentisering per enhet           | Implementerat (delad nyckel — se begränsning) |
| IA-5     | Authenticator Management                               | Master-nyckel till K_enc/K_mac via SHA-256-derivation      | Implementerat                                 |
| IA-6     | Authenticator Feedback                                 | E-Paper visar status (authenticating/authenticated/failed) | Implementerat                                 |
| IA-8     | Identification and Authentication (Non-Organizational) | Ej applicerbar — inga externa identiteter                  | Ej applicerbar                                |

### AU — Audit and Accountability

| Kontroll | Beskrivning             | SHALLOT-mappning                                                 | Status                            |
| -------- | ----------------------- | ---------------------------------------------------------------- | --------------------------------- |
| AU-2     | Event Logging           | Ogiltig HMAC, timeout, replay-försök detekteras i realtid        | Delvis (ingen persistent lagring) |
| AU-6     | Audit Record Review     | UNO Q MPU audit-logg planerad för nyckel-fingeravtryck           | Planerat (Phase 2)                |
| AU-12    | Audit Record Generation | Felkod genereras per ogiltigt paket (HMAC/timeout/okänd sändare) | Delvis                            |

### SC — System and Communications Protection

| Kontroll | Beskrivning                                | SHALLOT-mappning                                                       | Status                                   |
| -------- | ------------------------------------------ | ---------------------------------------------------------------------- | ---------------------------------------- |
| SC-8     | Transmission Confidentiality and Integrity | AES-128-CTR (konfidentialitet) + HMAC-SHA256 (integritet)              | Implementerat                            |
| SC-12    | Cryptographic Key Establishment            | UNO Q TRNG genererar master-nyckel; SHA-256 derivation för K_enc/K_mac | Implementerat (Phase 2) / Stub (Phase 1) |
| SC-13    | Cryptographic Protection                   | AES-128 + HMAC-SHA256 enligt NIST-godkända algoritmer                  | Implementerat                            |
| SC-20    | Secure Name/Address Resolution             | Ej applicerbar — ingen DNS/adressuppslagning                           | Ej applicerbar                           |
| SC-36    | Distributed Processing and Targeting       | Ej applicerbar — centraliserad fail-closed-logik                       | Ej applicerbar                           |

### SI — System and Information Integrity

| Kontroll | Beskrivning                    | SHALLOT-mappning                                                          | Status         |
| -------- | ------------------------------ | ------------------------------------------------------------------------- | -------------- |
| SI-3     | Malicious Code Protection      | Ej applicerbar — ingen kodexekvering från externa källor                  | Ej applicerbar |
| SI-4     | System Monitoring              | SeqWhitelist + retry-räknare övervakar paketflöde                         | Implementerat  |
| SI-10    | Information Input Validation   | HMAC-verifiering före bearbetning; protokollversion och MsgType valideras | Implementerat  |
| SI-13    | Predictable Failure Prevention | Retry-policy (3 försök) + fail-closed förhindrar oändliga loopar          | Implementerat  |

### IR — Incident Response

| Kontroll | Beskrivning                | SHALLOT-mappning                                                                 | Status         |
| -------- | -------------------------- | -------------------------------------------------------------------------------- | -------------- |
| IR-2     | Incident Response Training | Ej applicerbar — autonomt system                                                 | Ej applicerbar |
| IR-4     | Incident Handling          | Fail-closed + återgång till idle + visuell status = automatisk incidenshantering | Implementerat  |
| IR-6     | Incident Reporting         | E-Paper-status indikerar incident för operatör                                   | Implementerat  |
| IR-8     | Incident Response Plan     | Fail-closed-arkitektur definierar respons för alla felfall                       | Implementerat  |

### RA — Risk Assessment

| Kontroll | Beskrivning            | SHALLOT-mappning                                                                      | Status        |
| -------- | ---------------------- | ------------------------------------------------------------------------------------- | ------------- |
| RA-3     | Risk Assessment        | Hotmodellering (PRO-55), MITRE-mappning (PRO-65), framework-mappning (PRO-64, PRO-66) | Implementerat |
| RA-5     | Vulnerability Scanning | Kända sårbarheter dokumenterade; pen-test (PRO-63) planerat                           | Delvis        |

### CM — Configuration Management

| Kontroll | Beskrivning                | SHALLOT-mappning                                                | Status        |
| -------- | -------------------------- | --------------------------------------------------------------- | ------------- |
| CM-2     | Baseline Configuration     | Protokollspecifikation, LoRa-parametrar, pin-mapping = baslinje | Implementerat |
| CM-6     | Configuration Settings     | Fasta konfigurationer (frekvens, SF, BW, CR, nyckelderivation)  | Implementerat |
| CM-7     | Least Functionality        | Endast LoRa P2P-kommunikation; inga onödiga tjänster            | Implementerat |
| CM-8     | System Component Inventory | Tre enheter + bibliotek inventerade i GitHub/Linear             | Implementerat |

### PE — Physical and Environmental Protection

| Kontroll | Beskrivning                    | SHALLOT-mappning                                   | Status                 |
| -------- | ------------------------------ | -------------------------------------------------- | ---------------------- |
| PE-2     | Physical Access Authorizations | SHALLOT är i sig ett fysiskt åtkomstkontrollsystem | Implementerat (ärende) |
| PE-6     | Monitoring Physical Access     | Ej implementerat (ingen tamper-sensor)             | Ej implementerat       |
| PE-18    | Power and Equipment            | Breadboard-prototyp; ingen redundant ström         | Delvis                 |

### MA — Maintenance

| Kontroll | Beskrivning          | SHALLOT-mappning                                                 | Status         |
| -------- | -------------------- | ---------------------------------------------------------------- | -------------- |
| MA-4     | Nonlocal Maintenance | Ej applicerbar — ingen fjärrunderhåll möjlig (air-gapped design) | Ej applicerbar |

### MP — Media Protection

| Kontroll | Beskrivning        | SHALLOT-mappning                                                 | Status                    |
| -------- | ------------------ | ---------------------------------------------------------------- | ------------------------- |
| MP-5     | Media Transport    | UNO Q distribuerar nyckel via fysisk USB — air-gapped överföring | Implementerat (Phase 2)   |
| MP-6     | Media Sanitization | Nyckel i RAM nollställs vid strömavbrott (volatil lagring)       | Implementerat (naturligt) |

---

## C.5 NIST SP 800-53 — Sammanfattning

| Familj                                     | Relevanta kontroller mappade | Status                 |
| ------------------------------------------ | ---------------------------- | ---------------------- |
| AC (Access Control)                        | 5                            | Implementerat          |
| IA (Identification and Authentication)     | 4                            | Implementerat          |
| AU (Audit and Accountability)              | 3                            | Delvis / Planerat      |
| SC (System and Communications Protection)  | 4                            | Implementerat          |
| SI (System and Information Integrity)      | 4                            | Implementerat          |
| IR (Incident Response)                     | 3                            | Implementerat          |
| RA (Risk Assessment)                       | 2                            | Implementerat / Delvis |
| CM (Configuration Management)              | 4                            | Implementerat          |
| PE (Physical and Environmental Protection) | 3                            | Delvis                 |
| MA (Maintenance)                           | 1                            | Ej applicerbar         |
| MP (Media Protection)                      | 2                            | Implementerat          |

**Bedömning:** SHALLOT uppfyller SP 800-53-kontroller inom AC, IA, SC, SI, IR, CM och MP i hög grad. Största gapen: persistent audit-loggning (AU-6, AU-12) och fysisk tamper-detektering (PE-6) saknas i MVP. Dessa är dokumenterade och planerade.

---

## C.6 Källor

- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework (NIST.CSWP.29, februari 2024)
- NIST CSF 2.0 Core (kategorier och subkategorier): https://csf.tools/reference/nist-cybersecurity-framework/v2-0/
- CIS Controls v8.1: https://www.cisecurity.org/controls/v8 (juni 2024)
- NIST SP 800-53 Rev 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- NIST SP 800-53 kontrollfamiljer: https://www.saltycloud.com/blog/nist-800-53-control-families/
- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/ (version 3.0, 2026-05-12)
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- AES (FIPS 197): Advanced Encryption Standard
- SHA-256 (FIPS 180-4): Secure Hash Standard
