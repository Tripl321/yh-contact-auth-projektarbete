# Framework-mappning: MITRE ATT&CK T1078

**PRO-65** | Mappa SHALLOT:s skydd mot MITRE ATT&CK T1078 (Valid Accounts)
**Källa:** [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/) (version 3.0, senast ändrad 2026-05-12)
**Status:** Slutfört för T1078

---

## 1. Tekniköversikt

### T1078: Valid Accounts

> Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

T1078 beskriver hur en angripare erhåller och missbrukar giltiga kontouppgifter för att få obehörig åtkomst, upprätthålla persistence, eskalera privilegier eller undvika detektion. Komprometterade referenser kan användas för att kringgå åtkomstkontroller, och angripare kan välja att inte använda skadlig kod för att undvika upptäckt.

**Taktiker:** Initial Access, Persistence, Privilege Escalation, Defense Evasion

**Sub-tekniker:**

| ID | Namn | Relevans för SHALLOT |
|---|---|---|
| T1078.001 | Default Accounts | Hoj — stub-nyckel i Phase 1 |
| T1078.002 | Domain Accounts | Medelhög — delad nyckel över flera enheter |
| T1078.003 | Local Accounts | Medelhög — per-enhet SenderID men delad krypto |
| T1078.004 | Cloud Accounts | Ej applicerbar — ingen molninfrastruktur i MVP |

---

## 2. Sub-teknikanalys och SHALLOT-mappning

### 2.1 T1078.001 — Default Accounts

**MITRE-beskrivning:** Angripare missbrukar inbyggda eller fabriksinställda konton. Standardkonton inkluderar OS-konton (Guest, Administrator) och förkonfigurerade konton på nätverksenheter och IoT-enheter.

**SHALLOT-mappning:** SHALLOT Phase 1 använder en hårdkodad stub-master-nyckel (0x00–0x0F). Denna nyckel är känd och publicerad i källkoden, vilket är direkt jämförbart med ett standardkonto med fabrikslösenord. En angripare som läser källkoden eller reverse-engineerar firmware kan extrahera nyckeln och härleda K_enc och K_mac.

**Riskbedömning:** Hoj. Stub-nyckeln eliminerar all kryptografisk säkerhet i Phase 1 — en angripare med kännedom om nyckeln kan förfalska giltiga paket, dekryptera payload och utföra replay-attacker (inom sekvensnummerfönstret).

**Mitigering implementerad:**
- Phase 2: UNO Q (air-gapped STM32U585) genererar nycklar via hårdvaru-TRNG och distribuerar via USB (PRO-45, PRO-46)
- Nyckelderivation (K_enc, K_mac) separerar krypterings- och autentiseringsnycklar
- Nyckel-läckage begränsas: master-nyckel exponeras aldrig för MPU eller nätverk

**Kvarstående risk:** Fram till Phase 2-implementering är stub-nyckeln en aktiv sårbarhet.

### 2.2 T1078.002 — Domain Accounts

**MITRE-beskrivning:** Angripare missbrukar domänkontouppgifter hanterade av Active Directory eller liknande katalogtjänster. Komprometterade domänkonton kan användas för lateral rörelse och privileg-eskalering.

**SHALLOT-mappning:** SHALLOT har ingen domäninfrastruktur, men konceptet är applicerbart på den delade nyckelmodellen. Samma master-nyckel distribueras till både edge enforcement-nod och PAW. Om en enhet komprometteras kan angriparen extrahera nyckeln och impersonera vilken nod som helst i systemet.

Detta är analogt med T1078.002 eftersom en komprometterad "domänkontoinfomation" (master-nyckel) ger åtkomst till alla resurser i "domänen" (SHALLOT-nätverket).

**Riskbedömning:** Medelhög. Kompromiss av en fysisk enhet (extraktion av nyckel via JTAG/SWD eller firmware-reverse-engineering) komprometterar hela systemet.

**Mitigering implementerad:**
- SenderID (8 byte) identifierar varje nod unikt — mottagaren kan logga och granska vilken nod som skickade ett paket
- HMAC täcker SenderID — förhindrar spoofing av avsändaridentitet (men inte nyckelextraktion)
- Fail-closed: ogiltig HMAC eller okänd SenderID leder till nekad åtkomst

**Kvarstående risk:** Ingen per-enhets nyckel i Phase 1. Båda noderna derivar samma K_enc/K_mac. En angripare som komprometterar en nod kan förfalska paket från den andra noden. Framtida arbete: per-enhets nycklar distribuerade av UNO Q.

### 2.3 T1078.003 — Local Accounts

**MITRE-beskrivning:** Angripare missbrukar lokala kontouppgifter för att få åtkomst till individuella system. Lokala administratörskonton med samma lösenord över flera system är en särskild risk.

**SHALLOT-mappning:** Varje SHALLOT-nod har en unik SenderID (Edge: 0x0100000000000000, PAW: 0x0200000000000000), vilket fungerar som en "lokal konto-identifierare". Men eftersom båda noderna delar samma krypto-nycklar, är det skydd som SenderID ger begränsat till identifikation, inte till autentisering.

**Riskbedömning:** Medelhög. SenderID förhindrar spoofing av identitet (HMAC täcker fältet), men skyddar inte mot nyckelextraktion från en komprometterad enhet.

**Mitigering implementerad:**
- SenderID inkluderas i HMAC-beräkningen — manipulering upptäcks
- SeqWhitelist spårar sekvensnummer per SenderID — replay från en specifik nod förhindras
- Konstant-tidsjämförelse av HMAC förhindrar timing-attacker vid identifiering

**Kvarstående risk:** Ingen bindning mellan SenderID och specifik krypto-nyckel. Framtida arbete: nyckel per SenderID, så att kompromiss av en nod inte komprometterar andra noder.

### 2.4 T1078.004 — Cloud Accounts

**MITRE-beskrivning:** Angripare missbrukar molnkonton för åtkomst till molnresurser, API:er och SaaS-tjänster.

**SHALLOT-mappning:** Ej applicerbar. SHALLOT är ett fristående fysiskt system utan molnberoenden. Ingen molninfrastruktur, inga API:er, inga SaaS-tjänster. All autentisering sker lokalt över LoRa P2P.

**Riskbedömning:** Ingen.

---

## 3. MITRE-mitigeringar mappade till SHALLOT

### M1032 — Multi-factor Authentication

**MITRE-beskrivning:** Implementera MFA för konton för att förhindra obehörig åtkomst även om referenser komprometteras.

**SHALLOT-mappning:** SHALLOT implementerar kryptografisk challenge-response, vilket är en form av "something you have"-autentisering. PAW måste besitta K_mac för att producera en giltig HMAC-svar. Detta är inte MFA i traditionell mening (ingen användare interagerar), men challenge-response-mekanismen ger en motsvarande säkerhetsegenskap: autentisering kräver både posession av nyckeln och förmågan att svara på en specifik utmaning.

**Implementerade kontroller:**

| Aspekt | SHALLOT-implementation | MFA-motsvarighet |
|---|---|---|
| Factor 1 | Posession av K_mac (hårdvarubunden nyckel) | Something you have |
| Factor 2 | Korrekt HMAC-svar på slumpmässig challenge-nonce | Something you can compute |
| Nonce-ekoverifiering | Ej implementerad (se begränsning 9.4) | Saknas — förstärkning planerad |
| Replay-skydd | SeqWhitelist sliding-window (10) | Förhindrar återanvändning av "session" |

**Bedömning:** Delvis uppfyllt. Challenge-response ger kryptografisk autentisering, men saknar nonce-ekoverifiering vilket försvagar bindingen mellan challenge och response.

### M1027 — Password Policies

**MITRE-beskrivning:** Implementera starka lösenordspolicyer. Standardlösenord ska ändras omedelbart efter installation.

**SHALLOT-mappning:** SHALLOT använder inte lösenord — autentisering baseras på kryptografiska nycklar (128-bit AES). I Phase 2 genereras nycklar av STM32U585 TRNG (hårdvarubaserad slumptalsgenerator), vilket eliminerar "svaga lösenord" som attackyta.

**Implementerade kontroller:**

| Aspekt | SHALLOT-implementation |
|---|---|
| Nyckelgenerering | Hårdvaru-TRNG (STM32U585) i Phase 2 |
| Nyckellängd | 128 bit (AES-128) |
| Nyckelrotation | Ej implementerad (planerad för framtida) |
| Standardnyckel | Phase 1: stub 0x00–0x0F (sårbarhet). Phase 2: elimineras |

**Bedömning:** Delvis uppfyllt. Phase 1 stub-nyckel strider mot M1027. Phase 2 uppfyller principen genom hårdvaru-TRNG.

### M1026 — Privileged Account Management

**MITRE-beskrivning:** Granska behörighetsnivåer rutinmässigt. Begränsa överlappning av behörigheter mellan system.

**SHALLOT-mappning:** SHALLOT separerar krypterings- och autentiseringsnycklar via derivation (K_enc, K_mac), vilket är analogt med principen om minsta privilegie — varje nyckel har en specifik roll och kan inte användas för ett annat syfte.

**Implementerade kontroller:**

| Aspekt | SHALLOT-implementation |
|---|---|
| Nyckelseparation | K_enc (kryptering) och K_mac (HMAC) derivas separat via SHA-256 |
| Behörighetsnivåer | Edge = initierare, PAW = responder — fasta roller |
| Granskning | Audit-logg på UNO Q MPU (nyckel-fingeravtryck, inte nyckel) |
| Behörighetsöverlapp | Ingen — varje nod har en specifik roll |

**Bedömning:** Uppfylld genom nyckelderivation och rollseparation.

### M1018 — User Account Management

**MITRE-beskrivning:** Granska och hantera konton regelbundet. Inaktivera onödiga konton.

**SHALLOT-mappning:** Varje SHALLOT-nod identifieras av en unik SenderID. Systemet kan utökas med nya noder (nya SenderID:n) och noder kan avregistreras. I Phase 1 är antalet noder fast (Edge + PAW).

**Implementerade kontroller:**

| Aspekt | SHALLOT-implementation |
|---|---|
| Nod-identifiering | 8-byte SenderID per nod |
| Nod-registrering | Fast i Phase 1; dynamisk i framtida versioner |
| Nod-avregistrering | Ej implementerad (planerad) |
| Inaktiva noder | Ej spårade (planerat för framtida) |

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

## 4. SHALLOT:s skydd sammanfattade

### 4.1 Implementerade skydd mot T1078

| Skydd | Mekanism | T1078-aspekt motverkad |
|---|---|---|
| Challenge-response | HMAC-SHA256 med K_mac, slumpmässig nonce per session | Förfalskning av autentiseringssvar |
| Replay-skydd | SeqWhitelist sliding-window (10), bitmask | Återanvändning av fångade giltiga paket |
| Anti-DoS | HMAC verifieras före seq-konsumtion | Utötning av sekvensnummer-slots |
| Fail-closed | Ogiltig HMAC/timeout/okänd sändare nekas | Default-open förhindras |
| Konstant-tidsjämförelse | HMAC-jämförelse utan timing-läcka | Timing-attacker på autentisering |
| Nyckelderivation | K_enc och K_mac separata via SHA-256 | Nyckelåteranvändning elimineras |
| AES-CTR-kryptering | Payload krypterad med K_enc | Avlyssning av autentiseringsdata |
| SenderID i HMAC | Avsändaridentitet täcks av HMAC | Spoofing av nod-identitet |
| Version i HMAC | Protokollversion täcks av HMAC | Versionsnedgraderingsattack |
| MsgType i HMAC | Meddelandetyp täcks av HMAC | State confusion-attack |

### 4.2 Begränsningar identifierade mot T1078

| Begränsning | T1078-relevans | Fas |
|---|---|---|
| Stub-nyckel 0x00–0x0F | T1078.001 — Default Accounts | Phase 1 |
| Delad nyckel över alla noder | T1078.002/003 — kompromiss av en nod = kompromiss av alla | Phase 1–2 |
| Ingen per-enhets nyckel | T1078.003 — Local Accounts saknar individuell härdning | Phase 1–2 |
| Sekvensnummer i RAM | Replay möjlig efter omstart (inom fönster) | Alla faser |
| Nonce-eko ej verifierat | Response binder ej till specifik challenge | Phase 1 |
| Ingen nyckelrotation | Komprometterad nyckel förblir giltig permanent | Alla faser |
| Ingen nod-avregistrering | Komprometterad nod kan inte fjärravregistreras | Alla faser |

---

## 5. Taktisk mappning

MITRE ATT&CK T1078 används inom fyra taktiker. SHALLOT:s skydd mappas per taktik:

### 5.1 Initial Access

Angripare försöker få initial åtkomst till systemet genom att missbruka giltiga referenser.

| Angreppsscenarie | SHALLOT-skydd | Status |
|---|---|---|
| Angripare fångar LoRa-paket och återanvänder | SeqWhitelist + HMAC | Implementerat |
| Angripare extraherar stub-nyckel från firmware | Ej skyddad i Phase 1 | Sårbarhet — Phase 2 åtgärdar |
| Angripare förfalskar SenderID | HMAC täcker SenderID | Implementerat |
| Angripare manipulerar protokollversion | HMAC täcker Version | Implementerat |
| Angripare manipulerar meddelandetyp | HMAC täcker MsgType | Implementerat |

### 5.2 Persistence

Angripare upprätthåller åtkomst över tid.

| Angreppsscenarie | SHALLOT-skydd | Status |
|---|---|---|
| Återanvändning av fångat giltigt paket | SeqWhitelist förkastar dubbletter | Implementerat |
| Nyckelextraktion för permanent åtkomst | Ej skyddad (nyckel i klartext i RAM) | Sårbarhet — krypterad lagring planerad |
| Skapande av falsk nod-identitet | SenderID + HMAC | Implementerat |

### 5.3 Privilege Escalation

Angripare försöker utöka behörigheter.

| Angreppsscenarie | SHALLOT-skydd | Status |
|---|---|---|
| Edge-impersonation från PAW-nyckel | Delad nyckel möjliggör | Sårbarhet — per-enhets nycklar planerade |
| Manipulering av verifieringsordning | HMAC före seq (anti-DoS) | Implementerat |
| Kringgående av fail-closed | Ingen default-open existerar | Implementerat |

### 5.4 Defense Evasion

Angripare undviker upptäckt.

| Angreppsscenarie | SHALLOT-skydd | Status |
|---|---|---|
| Användning av giltig HMAC för att undvika detektion | Challenge-response kräver specifik nonce | Delvis — nonce-eko saknas |
| Manipulation av loggning | Audit-logg på UNO Q MPU (separat enhet) | Implementerat (Phase 2) |
| Avstörning av LoRa-frekvens | Retry-policy (3 försök) + fail-closed | Implementerat |

---

## 6. Fas-2-förbättringar

Följande förbättringar planerade för att stärka skyddet mot T1078:

| Förbättring | T1078-aspekt | Beroende | Prioritet |
|---|---|---|---|
| Ersätt stub-nyckel med UNO Q-nyckel | T1078.001 | PRO-45, PRO-46 | Hoj |
| Per-enhets nycklar (nyckel per SenderID) | T1078.002, T1078.003 | PRO-45 | Hoj |
| Nonce-ekoverifiering i edge | T1078 Defense Evasion | Inget | Medelhög |
| Krypterad nyckellagring i flash | T1078 Persistence | Inget | Medelhög |
| Nyckelrotation (periodisk) | T1078 Persistence | UNO Q-uppgradering | Låg |
| Nod-avregistrering (revoke) | M1018 | UNO Q-uppgradering | Låg |
| Flash-persistens av sekvensnummer | Replay efter omstart | Inget | Medelhög |

---

## 7. Referenser

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
