# 08 — Hotmodellering (PRO-55)

**Status:** Utkast 2026-09-15 | **Scope:** dockad UART-autentisering
(DEN↔PAW) + USB-nyckeldistribution så som de är **implementerade i detta
träd**. Varje mekanism nedan är märkt IMPLEMENTERAD eller DESIGN —
inget avsnitt antar funktioner som inte finns.

Fyller den reserverade platsen från `docs/02` §12.2 (`08-hotmodellering`,
PRO-55) och ersätter stubben på branchen `pro-55-threat-model`, som
antog icke-existerande mekanismer (sekvensnummer på dock-länken,
HMAC-täckta meddelandetyper, AES-CTR-krypterad radiotrafik).

Utanför scope: LoRa-transporten (`docs/00`, explicit ur scope — kod
finns i PAW men härdas inte här), MamaBear-SSH (läsande allowlist).

## 1. Tillgångar och förtroendegränser

| Tillgång | Var | Skydd (implementerat) |
|---|---|---|
| Master-nyckel (128 bit) | DEN- + PAW-SRAM | Aldrig flash; aldrig tråd utom USB-ceremonin; `secure_clear_key` (volatil wipe). OBS: DEN har f.n. inbränd dev-nyckel (F1) |
| `K_mac` | DEN- + PAW-SRAM | Härledd `SHA-256(master\|\|"MAC")[:16]` vid reception; all HMAC använder den; aldrig på tråd |
| `K_enc` | SRAM-buffert | Reserverad, oanvänd, nollställd — härledning ej implementerad |
| Nonce (64 bit) | DEN-SRAM per session | RP2350-TRNG per CHALLENGE (PRO-51); noll-nonce avvisas; raderas efter beslut |
| HMAC-svar (32 B) | UART-tråd | Sänds öppet per design — oförfalskbart utan `K_mac`, behöver ingen sekretess |
| Fingerprint (4 B) | USB + loggar | Offentlig per design (jämförelsevärde) |
| Skälkoder (0–7) | USB-logg | Icke-hemliga per design (`docs/13` §2; särskiljer felklasser — se R6) |

| Gräns | Angriparläge | Bärande antagande |
|---|---|---|
| USB UNO Q↔nod | Passiv avlyssning / egen värd | Fysisk kabel + luftgap (FR-NP-002) + operatörsknapp (FR-NP-005). **Inget krypto** — mastern går i klartext + CRC32 |
| Dock-UART (pogo) | Godtyckliga ramar vid pinåtkomst | CRC ger ingen äkthet; säkerheten vilar på HMAC + färsk nonce + fail-closed-parser |
| USB-seriell logg | Passiv observatör | Aldrig nyckelbyte (källkods­granskat i PRO-47-tester); skälkoder + fingerprint accepteras |
| E-paper/LED | Visuell observatör | Statusikoner + beviljandetext, ingen PII |
| Matningsspänning | Kraftbrytning | SRAM dör med kraften (FR-NP-009/010); ingen persistens att utvinna |
| Stulen nod | Full SRAM-dump | Inget secure element — utvunnen master oskiljbar från äkta nod |

## 2. STRIDE (endast implementerat beteende)

| Hot | Yta | Mitigering (implementerad) | Restrisk |
|---|---|---|---|
| Spoofing (falsk PAW) | Dock-UART | HMAC under `K_mac`, färsk TRNG-nonce per session, konstanttids­jämförelse (`den_ct_compare`, `docs/07`), 2 s-deadline, engångs­beslut | Stulen PAW oskiljbar (R2); ingen spärrnings­mekanism implementerad |
| Spoofing (falsk DEN: ACK/RESULT) | Dock + LoRa | Endast display­påverkan; dock-ACK grindad på väntande svar (`paw_ack_pending`) — LoRa-RESULT ogrindad (F4); DEN fattar beslut lokalt | Ingen auth-bypass möjlig |
| Tampering (ramar) | Dock-UART | Exakta typstorlekar, `LEN ≤ 64`, okänd typ förkastas, CRC-fel kasserar hel ram, resynk-budget 64 B, 100 ms byte-timeout | Angripare med pinåtkomst smider godtyckliga ramar — inneslutet till tillgänglighet (neka), aldrig bevilja |
| Tampering (USB-ceremoni) | USB | CRC32 + strikt tag/längd + wipe vid varje fel; operatörsknapp (UNO Q) | Klartext-master vid avlyssning/egen värd (R1) |
| Repudiation | Bevisföring | Fingerprint i STORED + live USB-logg av verdict + skälkod | Ingen persistent försöks­historik per design (NFR-PRV-003) — begränsad forensik |
| Information disclosure | Tråd/logg/display | Inga nyckelbyte på någon tråd (PRO-47-källskydd); HMAC-svar offentliga per design | Skälkods­orakel (R6); HMAC-orakel på valda noncer (R7); dev-nyckel i träd (F1) |
| DoS (skräpramar) | Dock-UART | Resynk/timeout/sessionsgap-pacing; e-paper degraded-läge blockerar aldrig auth | Pinstörning kan ej förhindras; ALARM obrukbart mitt i session (oväntad typ dödar den — R9) |
| Elevation (persistens) | Flash/SRAM | Ingen flash-skrivning av nycklar; boot rensar (PAW `secure_clear_key` i `setup`); PAW-LoRa nekar oprovisionerad | DEN nekar aldrig p.g.a. saknad nyckel — dev-nyckel alltid inbränd (F1); ingen rotation (R11) |

## 3. Replay-risk

Dock-länken har **inga sekvensnummer** (medvetet — se §4).
Återspelningsskyddet är tredelat, allt implementerat och testat
(`tests/test_pro88_den.py`, `tests/test_pro62_failure_scenarios.py`):

1. **Färsk nonce per session** — 64-bit RP2350-TRNG per CHALLENGE
   (PRO-51); noll-nonce avvisas fail-closed.
2. **HMAC-bindning till aktuell nonce** — implementerat låst beteende är
   `HMAC-SHA256(K_mac, nonce)`. OBS-DIVERGENS: `docs/11` §3/§5 anger
   `HMAC(K, epoch || nonce)`, men ingen epoch distribueras över
   dock-länken och båda firmwaresidorna binder enbart noncen med härledd
   `K_mac`. Återspelnings­skyddet bärs av nonce-fräschören, inte av epoch —
   spec-texten behöver ett protokoll­beslut (F2).
3. **Engångsbeslut per session** — första giltiga RESPONSE avgör; sena/
   dubblerade svar möter `AUTHENTICATED`/`DENIED` eller raderad nonce
   (`STALE_RESPONSE`); deadline exakt 2 s.

Konsekvens: ett avlyssnat RESPONSE är värdelöst mot ny nonce; leverans
två gånger inom fönstret är ofarlig (beslutet redan fattat); sent giltigt
svar nekas (`TIMEOUT`).

Kuvert-epokens återspelningsskydd (`docs/12` §7, `docs/14` §4.8) är
**DESIGN**, ej implementerat: dagens USB-ceremoni har inget replay-skydd
utöver 10 s-fönster + engångs­sessionstillstånd + operatörsknapp.

## 4. Sekvensnummer

| Var | Status | Kommentar |
|---|---|---|
| Dock-UART | **Finns inte** | Challenge-response med färsk nonce ger replay-skydd utan synkroniserat tillstånd: inga räknare att desynka, inget flash-slitage, omstarts­säkert per konstruktion |
| Kuvert-epoch (`epoch`/`lastEpoch`) | DESIGN (`docs/12` §7, `docs/14` §4.8) | Monoton SRAM-räknare; ingen firmware; `libraries/EnvelopeCrypto` saknas i trädet |
| IV+sekvensnummer för AES-CTR (`docs/07`) | DESIGN-påstående | `docs/07` beskriver IV-format med sekvensnummer — ingen CTR-kod, ingen räknare och ingen krypterad trafik finns i firmware. Behandla `docs/07` §IV som kravspec för framtida kryptering, inte som nuläge |
| HEARTBEAT/ALARM | Inget nummer, ingen auth | Närvaro-/larmhintar endast; aldrig auth-relevanta |

## 5. Manipulering av meddelandetyper

`TYPE`-fältet täcks av CRC32, **inte av HMAC** — en angripare med
pinåtkomst kan sätta om typ/längd/payload fritt (CRC är beräkningsbar).
(Uppgiften i stubben att "version och typ ingår i HMAC" stämmer inte för
dock-länken.) Skadan är innesluten per konstruktion:

- DEN i session accepterar endast `RESPONSE` med exakt 32 B + giltig HMAC
  under aktuell nonce; allt annat → `DENIED` (loopback-testat: egen
  CHALLENGE tillbaka ger `UNEXPECTED_TYPE`, `docs/13` acceptanstest 1).
- PAW besvarar endast `CHALLENGE` med exakt 8 B; `HEARTBEAT`/`ACK`/`ALARM`/
  `RESPONSE` inbound besvaras aldrig. **Undantag (F3):** dock-svaret är
  inte grindat på `keyStored` — oprovisionerad PAW besvarar CHALLENGE med
  HMAC under nollställd `kMac` och tänder AUTHENTICATING. Ingen bypass
  (DEN förkastar), men sändning + display sker utan credential —
  rekommenderad åtgärd: grinda på `keyStored` som LoRa-stigen redan gör.
- `LEN > 64` avvisas innan fler byte läses; fel storlek för känd typ
  förkastas (`DEN_ERR_LENGTH`).
- Tråden har inget versionsfält — ingen nedgraderingsyta.
- Förfalskad ACK/RESULT påverkar endast PAW-displayen: dock-ACK är grindad
  på `paw_ack_pending` (sen ACK ignoreras); LoRa-RESULT är **ogrindad** —
  obeställd `RESULT 0x01` tänder AUTHENTICATED även oprovisionerat (F4,
  display-only, rekommenderad åtgärd: grinda på `STATE_WAITING_FOR_RESULT`).

## 6. Nyckelåteranvändning

- **Delad master DEN+PAW** är nödvändig parvis tillit: en ceremoni
  installerar samma nyckel på båda. Komprometterad nod = komprometterad
  parrelation; enda återställningen är om-ceremoni.
- **Domänseparation vid härledning** (`docs/07` §Nyckelhärledning):
  `K_mac = SHA-256(master||"MAC")[:16]` används för all HMAC (PRO-49);
  `K_enc = SHA-256(master||"ENC")[:16]` är reserverad — buffert finns men
  härledning/användning är ej implementerad, så ingen återanvändnings­konflikt
  existerar i praktiken. (Stubbens påstående att CTR/HMAC-separation är
  driftsatt gäller endast HMAC-sidan; ingen krypteringstrafik finns.)
- **Samma `K_mac` över sessioner** är per design: fräschören kommer från
  noncen, inte från rotation. Samma `K_mac` används även på LoRa-stigen
  (transport­återanvändning — noteras eftersom LoRa-kod finns men är ur
  scope för härdning).
- **Ingen rotationsprocedur och ingen spärrning implementerad**:
  återställning = ny ceremoni. (Blocklist/Ed25519-spår finns inte i detta
  träd.)
- **Operatörs­ledet**: samma master installeras på båda noderna från en
  ceremoni; MPU/Bridge hanterar endast publika värden (fingerprints,
  status) per FR-NP-006/012.

## 7. Restrisker och fynd

| # | Fynd/risk | Allvar | Läge |
|---|---|---|---|
| F1 | **Inbränd delad dev-nyckel i DEN** (`DEN_DEV_KEY` 00..0F + `#warning`); DEN nekar aldrig p.g.a. saknad nyckel | Hög (pre-prod) | Ersätt med provisionerad nyckel före produktion (`docs/13` §7 rad 1); verifiera att ingen 00..0F-vektor finns kvar i bygget |
| F2 | **Spec/impl-divergens**: `docs/11` anger epoch-bunden HMAC, firmware binder nonce-only med `K_mac` | Mellan | Kräver protokoll­beslut; ändra inte ensidigt (bryter interop). Replay-skyddet påverkas inte (nonce bär det) |
| F3 | **Oprovisionerad PAW besvarar dock-CHALLENGE** (ingen `keyStored`-grind; HMAC under noll-nyckel + AUTHENTICATING-display) | Låg (ingen bypass) | Grinda dock-svaret på `keyStored` |
| F4 | **LoRa-RESULT ogrindad** (obeställd 0x01 tänder AUTHENTICATED, även oprovisionerat; display-only) | Låg | Grinda på `STATE_WAITING_FOR_RESULT` |
| R1 | USB-ceremonin sänder mastern i klartext | Mellan | Fysisk kabel + luftgap + knapp idag; designad fix = kuvert v2 (X25519+AES-GCM+epoch, `docs/14`) — ej implementerad |
| R2 | SRAM-dump vid stulen nod (inget secure element) | Hög vid fysisk stöld | Framtid: ATECC608A/SE050 (`docs/13` §7) |
| R3 | Egenhändiga SHA-256-implementationer (flera kopior) ogranskade | Mellan | Oberoende krypto­granskning krävs; KAT-täckning ersätter ej audit |
| R4 | TRNG-kvalitet overifierad på kisel (RP2350 + STM32U585) | Mellan | Bänk: statistiska RNG-tester på hårdvara |
| R5 | Enstaka SRAM-bitfel oupptäckta (endast noll-nonce avvisas) | Låg | Accepteras tills fingerprint-kontroll vid hämtning införs |
| R6 | Skälkoder särskiljer felklasser (bänkorakel) | Info | Accepterat; läcker aldrig nyckelmaterial |
| R7 | HMAC-orakel: PAW besvarar angriparvalda noncer (dock + LoRa) | Låg | HMAC-SHA256 oförfalskbar från orakelfrågor; accepterat |
| R8 | 64-bit nonce, födelsedags­gräns ~2³² sessioner | Försumbar | Sessions­kadens gör kollision opraktisk |
| R9 | ALARM/HEARTBEAT oautentiserade; ALARM dödar pågående session | Låg (tillgänglighet) | Per design; aldrig beviljande |
| R10 | LoRa-stig utan scope-härdning (samma `K_mac`, ogrindad RESULT) | Låg–Mellan | Håll LoRa ur scope tills separat uppgift tar TX-only/larmkana­len |
| R11 | Ingen rotation/forward secrecy | Mellan | Om-ceremoni enda vägen; definiera rotations­procedur före produktion |
| R12 | Operatörstvång / illasinnad värd vid ceremonin | Utanför protokoll | Fysisk tillträdes­kontroll + off-device-audit (samma gräns som `docs/12` §9) |
| R13 | Sidokanaler (effekt/EM/timing) | Okänd | Labbutrustning krävs; ingen analys gjord |

## 8. AES-CCM som framtida härdning

Status: **ej implementerat** (ingen AES-algoritmkod i firmware — endast
nyckelstorleken `AES_KEY_SIZE`; ingen CCM/GCM/ECB/CTR). `docs/07`
rekommenderar CCM via pico-hsm/wolfSSL som post-MVP; nedan preciserar vad
som då krävs. Beslutet är inte taget — kuvertdesignen (`docs/12`/`docs/14`)
har i stället valt AES-128-GCM; CCM är ett *alternativ* med mindre
Galois-maskineri för korta ramar.

- **Vad det skulle tillföra**: AEAD (sekretess + äkthet, en nyckel) för
  USB-ceremonin (ersätter klartext-mastern, R1) och eventuellt skyddade
  dock-ramar. Eliminerar separat kryptera-sedan-MAC-komplexitet.
- **Förutsättningar** (måste finnas först): IV-disciplin — CCM-nonce-
  återanvändning läcker klartext-XOR och möjliggör förfalskning, så den
  kräver precis den sekvens/epoch-infrastruktur som saknas idag (§4);
  nyckelhärledning per syfte (befintligt MAC/ENC-mönster utökas med t.ex.
  `"WRAP"`/`"DOCK"`); testvektorer + interop-pinnar; timing­granskning av
  biblioteks­valet (pico-hsm/wolfSSL per `docs/07`).
- **Vad det inte lagar**: R2 (extraktion), R4 (TRNG), R6/R7 (orakel),
  R12 (tvång), DoS eller sidokanaler. CCM ersätter inte nonce-fräschör,
  fail-closed-tillstånd eller operatörs­ceremonin.

## 9. Verifieringsstatus (uppmätt 2026-09-15: 175 passed)

| Påstående | Automatiserat | Bänk |
|---|---|---|
| Ramformat/CRC/resynk/timeout | `tests/test_pro87_uart.py` (15) | Signal­integritet pogo (`docs/13` §3) |
| DEN fail-closed + deadline + ct-jämförelse | `tests/test_pro88_den.py` (17) | Loopback/tystnad acceptanstest 1–9 (`docs/13` §3) |
| PAW responder + display­tillstånd | `tests/test_pro84_paw.py` | Visuell e-paper-kontroll |
| Nyckellagring SRAM + wipe | `tests/test_pro47_key_storage.py` | Volatilitet vid kraftbortfall (FR-NP-009/010) |
| Distribution USB + fingerprint | `tests/test_pro46_usb_distribution.py` | Ceremoni + knapp på hårdvara (`docs/15`) |
| Nyckelgenerering TRNG | `tests/test_pro45_key_generation.py` | Statistisk RNG-kvalitet (R4) |
| HMAC/KDF/nonce-vektorer | `test_pro50/49/51_hmac/paw` | — |
| Helflöde + felscenarier | `tests/test_pro61_e2e_integration.py`, `test_pro62_failure_scenarios.py` | Sammansatt docka (`docs/15`) |
| F1–F4, R1–R13, CCM | Detta dokument (granskning) | Respektive rad ovan |

## Referenser

- Trådformat + HMAC-beteende (notera F2-divergensen): `docs/11-dockat-uart-protokoll.md`
- Tillståndsmaskin + acceptans + restrisker: `docs/13-pro-53-fail-closed.md`
- Säkerhetsdesign (KDF, ct-jämförelse, CCM-riktning): `docs/07-sakerhetsdesign.md`
- Kuvert (referens): `docs/12-envelope-protocol.md`; provisionering v2 (DESIGN): `docs/14-provisioning-v2-design.md`
- Hårdvaruguider: `docs/15-pro-45-46-hardware-verification.md`; arkitektur-reservation: `docs/02` §12.2
- Krav: `docs/01-kravspecifikation.md` (FR-NP/FR-CR/NFR-SEC); scope: `docs/00-scope.md`
