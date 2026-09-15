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
finns i PAW men härdas inte här), MamaBear-SSH (läsande allowlist),
FIDO2-härdningsspåret (`docs/19`, eget designdokument).

## 1. Tillgångar och förtroendegränser

| Tillgång | Var | Skydd (implementerat) |
|---|---|---|
| Master-nyckel (128 bit) | DEN- + PAW-SRAM | Aldrig flash; aldrig tråd utom USB-ceremonin; volatil wipe (PAW på alla felvägar; DEN nollställer buffertar — se F1); flagg-grindad hämtning utan nollvalidering |
| `K_mac` | DEN- + PAW-SRAM | Härledd `SHA-256(master\|\|"MAC")[:16]` vid reception; all HMAC använder den; aldrig på tråd |
| `K_enc` | SRAM-buffert | Reserverad, oanvänd, nollställd — härledning ej implementerad |
| Nonce (64 bit) | DEN-SRAM per session | RP2350-TRNG per CHALLENGE (PRO-51); noll-nonce avvisas; raderas efter beslut |
| HMAC-svar (32 B) | UART-tråd | Sänds öppet per design — oförfalskbart utan `K_mac`, behöver ingen sekretess |
| Blocklist + Ed25519-nycklar | DEN-SRAM / UNO Q | Versionshanterad, Ed25519-signerad (PRO-98); privat nyckel endast UNO Q — trust root ännu placeholder (F3) |
| Fingerprint (4 B) | USB + loggar | Offentlig per design (jämförelsevärde) |
| Skälkoder (0–7) | USB-logg | Icke-hemliga per design (`docs/13` §2; särskiljer felklasser — se R6) |

| Gräns | Angriparläge | Bärande antagande |
|---|---|---|
| USB UNO Q↔nod | Passiv avlyssning / egen värd | Fysisk kabel + luftgap (FR-NP-002) + operatörsknapp (FR-NP-005). **Inget krypto** — mastern går i klartext + CRC32 |
| Dock-UART (pogo) | Godtyckliga ramar vid pinåtkomst | CRC ger ingen äkthet; säkerheten vilar på HMAC + färsk nonce + fail-closed-parser |
| USB-seriell logg | Passiv observatör | Aldrig nyckelbyte (PRO-47-källskydd); skälkoder + fingerprint accepteras |
| E-paper/LED | Visuell observatör | Statusikoner + beviljandetext, ingen PII |
| Matningsspänning | Kraftbrytning | SRAM dör med kraften (FR-NP-009/010); ingen persistens att utvinna |
| Stulen nod | Full SRAM-dump | Inget secure element — utvunnen master oskiljbar från äkta nod |

## 2. STRIDE (endast implementerat beteende)

| Hot | Yta | Mitigering (implementerad) | Restrisk |
|---|---|---|---|
| Spoofing (falsk PAW) | Dock-UART | HMAC under `K_mac`, färsk TRNG-nonce per session, konstanttidsjämförelse (`den_ct_compare`, `docs/07`), 2 s-deadline, engångsbeslut; spärrning via PRO-98 efter giltig HMAC | Stulen PAW oskiljbar (R2); spärrning inaktiv tills trust root pinnad (F3) |
| Spoofing (falsk DEN: ACK/RESULT) | Dock + LoRa | Endast displaypåverkan; dock-ACK grindad på väntande svar (`paw_ack_pending`) — LoRa-RESULT ogrindad (F2); DEN fattar beslut lokalt | Ingen auth-bypass möjlig |
| Tampering (ramar) | Dock-UART | Exakta typstorlekar, `LEN ≤ 64`, okänd typ förkastas, CRC-fel kasserar hel ram, resynk-budget 64 B, 100 ms byte-timeout | Angripare med pinåtkomst smider godtyckliga ramar — inneslutet till tillgänglighet (neka), aldrig bevilja |
| Tampering (USB-ceremoni) | USB | CRC32 + strikt tag/längd; PAW wipar nyckel vid varje fel; operatörsknapp (UNO Q) | Klartext-master vid avlyssning/egen värd (R1); DEN wipar ej lagrad nyckel vid fel (F1) |
| Repudiation | Bevisföring | Fingerprint i STORED + live USB-logg av verdict + skälkod | Ingen persistent försökshistorik per design (NFR-PRV-003) — begränsad forensik |
| Information disclosure | Tråd/logg/display | Inga nyckelbyte på någon tråd (PRO-47-källskydd); HMAC-svar offentliga per design | Skälkodsorakel (R6); HMAC-orakel på valda noncer (R7) |
| DoS (skräpramar) | Dock-UART | Resynk/timeout/sessionsgap-pacing; e-paper degraded-läge blockerar aldrig auth | Pinstörning kan ej förhindras; ALARM obrukbart mitt i session (oväntad typ dödar den — R9) |
| Elevation (persistens) | Flash/SRAM | Ingen flash-skrivning av nycklar; boot rensar (PAW `secure_clear_key` i `setup`; DEN noll-init + `key_provisioned = 0`); oprovisionerad nekar på båda sidor | Ingen rotation (R11); DEN-hygien avviker (F1) |

## 3. Replay-risk

Dock-länken har **inga sekvensnummer** (medvetet — se §4).
Återspelningsskyddet är tredelat, allt implementerat och testat
(`tests/test_pro88_den.py`, `tests/test_pro62_failure_scenarios.py`
inkl. trådnivå):

1. **Färsk nonce per session** — 64-bit RP2350-TRNG per CHALLENGE
   (PRO-51); noll-nonce avvisas fail-closed.
2. **HMAC-bindning till aktuell nonce** — låst beteende
   `HMAC-SHA256(K_mac, nonce)` med härledd nyckel (avvikelsenot,
   `docs/11` §3; epoch finns endast i provisioneringsprotokollet).
3. **Engångsbeslut per session** — första giltiga RESPONSE avgör; sena/
   dubblerade svar möter `AUTHENTICATED`/`DENIED` eller raderad nonce
   (`STALE_RESPONSE`); deadline exakt 2 s.

Konsekvens: ett avlyssnat RESPONSE är värdelöst mot ny nonce; leverans
två gånger inom fönstret är ofarlig (beslutet redan fattat); sent giltigt
svar nekas (`TIMEOUT`).

Kuvert-epokens återspelningsskydd (`docs/12` §7, `docs/14` §4.8) är
**DESIGN**, ej implementerat: dagens USB-ceremoni har inget replay-skydd
utöver 10 s-fönster + engångssessionstillstånd + operatörsknapp.

## 4. Sekvensnummer

| Var | Status | Kommentar |
|---|---|---|
| Dock-UART | **Finns inte** | Challenge-response med färsk nonce ger replay-skydd utan synkroniserat tillstånd: inga räknare att desynka, inget flash-slitage, omstartssäkert per konstruktion |
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
- PAW besvarar endast `CHALLENGE` med exakt 8 B och endast med lagrad
  nyckel (`keyStored`-grind i `handleDockAuth`, PRO-94-testad);
  `HEARTBEAT`/`ACK`/`ALARM`/`RESPONSE` inbound besvaras aldrig, och
  oprovisionerad PAW sänder ingenting.
- `LEN > 64` avvisas innan fler byte läses; fel storlek för känd typ
  förkastas (`DEN_ERR_LENGTH`).
- Tråden har inget versionsfält — ingen nedgraderingsyta; interop är låst
  av avvikelsenoten + KAT-vektorer (`docs/11`, `tests/test_pro87_uart.py`).
- Förfalskad ACK/RESULT påverkar endast PAW-displayen: dock-ACK är grindad
  på `paw_ack_pending` (sen ACK ignoreras); LoRa-RESULT är **ogrindad** —
  obeställd `RESULT 0x01` tänder AUTHENTICATED även oprovisionerat (F2,
  display-only, rekommenderad åtgärd: grinda på `STATE_WAITING_FOR_RESULT`).

## 6. Nyckelåteranvändning

- **Delad master DEN+PAW** är nödvändig parvis tillit: en ceremoni
  installerar samma nyckel på båda. Komprometterad nod = komprometterad
  parrelation; enda återställningen är om-ceremoni.
- **Domänseparation vid härledning** (`docs/07` §Nyckelhärledning):
  `K_mac = SHA-256(master||"MAC")[:16]` används för all HMAC (PRO-49);
  `K_enc = SHA-256(master||"ENC")[:16]` är reserverad — buffert finns men
  härledning/användning är ej implementerad, så ingen återanvändningskonflikt
  existerar i praktiken. (Stubbens påstående att CTR/HMAC-separation är
  driftsatt gäller endast HMAC-sidan; ingen krypteringstrafik finns.)
- **Samma `K_mac` över sessioner** är per design: fräschören kommer från
  noncen, inte från rotation. Samma `K_mac` används även på LoRa-stigen
  (transportåteranvändning — noteras eftersom LoRa-kod finns men är ur
  scope för härdning).
- **Spärrning (PRO-98)** kontrollerar nyckelfingerprint *efter* giltig HMAC
  (max 16 poster, Ed25519-signerad distribution, privat nyckel endast
  UNO Q) — men DEN:s inbäddade publiknyckel är f.n. en noll-placeholder,
  så verifiering kan aldrig lyckas och spärrning är inaktiv tills riktig
  trust root pinnas (F3). **Ingen rotationsprocedur** finns i övrigt.
- **Operatörsledet**: samma master installeras på båda noderna från en
  ceremoni; MPU/Bridge hanterar endast publika värden (fingerprints,
  status) per FR-NP-006/012.

## 7. Restrisker och fynd

| # | Fynd/risk | Allvar | Läge |
|---|---|---|---|
| F1 | **DEN-hygien avviker**: `secure_clear_key` är död kod (definierad, anropas aldrig, nollställer ej flaggan); timeout/fel nollställer endast buffertar. Misslyckad omprovisionering behåller gammal giltig nyckel (fail-safe riktning, men divergerar från PAW som wipar) | Låg–Mellan | Rensa som PAW: anropa vid handshake/timeout/fel + `key_provisioned = 0` i wipen |
| F2 | **LoRa-RESULT ogrindad** (obeställd 0x01 tänder AUTHENTICATED, även oprovisionerat; display-only) | Låg | Grinda på `STATE_WAITING_FOR_RESULT` |
| F3 | **Blocklist inaktiv**: DEN-publiknyckel är noll-placeholder; max 16 poster; kontroll först efter HMAC | Mellan (spärrning saknas) | Pinna riktig trust root + distributionstest innan spärrning påstås fungera |
| R1 | USB-ceremonin sänder mastern i klartext | Mellan | Fysisk kabel + luftgap + knapp idag; designad fix = kuvert v2 (X25519+AES-GCM+epoch, `docs/14`) — ej implementerad |
| R2 | SRAM-dump vid stulen nod (inget secure element) | Hög vid fysisk stöld | Framtid: ATECC608A/SE050 (`docs/13` §7) |
| R3 | Egenhändiga SHA-256-implementationer (flera kopior) ogranskade | Mellan | Oberoende kryptogranskning krävs; KAT-täckning ersätter ej audit |
| R4 | TRNG-kvalitet overifierad på kisel (RP2350 + STM32U585) | Mellan | Bänk: statistiska RNG-tester på hårdvara |
| R5 | Enstaka SRAM-bitfel oupptäckta (endast noll-nonce avvisas; ingen nollvalidering av master) | Låg | Accepteras tills fingerprint-kontroll vid hämtning införs |
| R6 | Skälkoder särskiljer felklasser (bänkorakel) | Info | Accepterat; läcker aldrig nyckelmaterial |
| R7 | HMAC-orakel: PAW besvarar angriparvalda noncer (dock grindad på nyckel, LoRa grindad på nyckel) | Låg | HMAC-SHA256 oförfalskbar från orakelfrågor; accepterat |
| R8 | 64-bit nonce, födelsedagsgräns ~2³² sessioner | Försumbar | Sessionskadens gör kollision opraktisk |
| R9 | ALARM/HEARTBEAT oautentiserade; ALARM dödar pågående session | Låg (tillgänglighet) | Per design; aldrig beviljande |
| R10 | LoRa-stig utan scope-härdning (samma `K_mac`, ogrindad RESULT) | Låg–Mellan | Håll LoRa ur scope tills separat uppgift tar TX-only/larmkanalen |
| R11 | Ingen rotation/forward secrecy | Mellan | Om-ceremoni enda vägen; definiera rotationsprocedur före produktion |
| R12 | Operatörstvång / illasinnad värd vid ceremonin | Utanför protokoll | Fysisk tillträdeskontroll + off-device-audit (samma gräns som `docs/12` §9) |
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
  `"WRAP"`/`"DOCK"`); testvektorer + interop-pinnar; timinggranskning av
  biblioteksvalet (pico-hsm/wolfSSL per `docs/07`).
- **Vad det inte lagar**: R2 (extraktion), R4 (TRNG), R6/R7 (orakel),
  R12 (tvång), DoS eller sidokanaler. CCM ersätter inte nonce-fräschör,
  fail-closed-tillstånd eller operatörsceremonin.

## 9. Verifieringsstatus (uppmätt 2026-09-15: 225 passed)

| Påstående | Automatiserat | Bänk |
|---|---|---|
| Ramformat/CRC/resynk/timeout | `tests/test_pro87_uart.py` (15) | Signalintegritet pogo (`docs/13` §3) |
| DEN fail-closed + deadline + ct-jämförelse | `tests/test_pro88_den.py` (26, inkl. PRO-98) | Loopback/tystnad acceptanstest 1–9 (`docs/13` §3) |
| PAW responder + keyStored-grind + display | `tests/test_pro84_paw.py` + `tests/test_pro94_security_review.py` | Visuell e-paper-kontroll; oprovisionerad tiger på docka |
| Nyckellagring SRAM + wipe | `tests/test_pro47_key_storage.py` | Volatilitet vid kraftbortfall (FR-NP-009/010) |
| Distribution USB + fingerprint | `tests/test_pro46_usb_distribution.py` | Ceremoni + knapp på hårdvara (`docs/15`) |
| Nyckelgenerering TRNG | `tests/test_pro45_key_generation.py` | Statistisk RNG-kvalitet (R4) |
| HMAC/KDF/nonce-vektorer | `tests/test_pro50/49/51_*.py` | — |
| Helflöde + felscenarier (inkl. trådnivå) | `tests/test_pro61_e2e_integration.py`, `tests/test_pro62_failure_scenarios.py` | Sammansatt docka (`docs/15`); kvarvarande beroenden `docs/13` §9 |
| Simulering auth-scenarier | `shallot simulate auth` (CLI) | Ingen hårdvara berörs (SIMULATED) |
| F1–F3, R1–R13, CCM | Detta dokument (granskning) | Respektive rad ovan |

## Referenser

- Trådformat + låst HMAC-beteende: `docs/11-dockat-uart-protokoll.md`
- Tillståndsmaskin + acceptans + restrisker + kvarvarande beroenden: `docs/13-pro-53-fail-closed.md`
- Säkerhetsdesign (KDF, ct-jämförelse, CCM-riktning): `docs/07-sakerhetsdesign.md`
- Kuvert (referens): `docs/12-envelope-protocol.md`; provisionering v2 (DESIGN): `docs/14-provisioning-v2-design.md`
- Hårdvaruguider: `docs/15-pro-45-46-hardware-verification.md`; arkitektur-reservation: `docs/02` §12.2
- Krav: `docs/01-kravspecifikation.md` (FR-NP/FR-CR/NFR-SEC); scope: `docs/00-scope.md`
