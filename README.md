# YH LoRa Auth Projektarbete

## Projektbeskrivning

Challenge-response autentisering över dockad UART (Serial1) med AES-128 och HMAC-SHA256.

Ett IoT-säkerhetsprojekt som demonstrerar kryptografisk autentisering mellan
två noder. En DEN (Raspberry Pi Pico 2) utmanar ett ID-kort
(Adafruit Feather RP2350) med en nonce över kontaktbaserad UART-docka.
ID-kortet svarar med HMAC-SHA256(AES-128-nyckel, nonce). Status visas på en
e-Paper-display. LoRa är archiverat i detta repo (se `docs/architecture-pivot-2026-09-09.md`).

## Arkitektur

- **PLC**: Raspberry Pi Pico 2 (RP2350A) + Waveshare Core1262-868M (SX1262 LoRa)
- **ID-kort**: Adafruit Feather RP2350 + Core1262-868M + 1.54" Waveshare e-Paper
- **Key Authority**: Arduino UNO Q (Qualcomm QRB2210 + STM32U585) -- genererar AES-128-nycklar, distribuerar via USB till bada noder

## Kryptografiskt flode

1. UNO Q genererar en AES-128-nyckel
2. Nyckeln distribueras via USB till bada noder (DEN och PAW)
3. DEN skickar en nonce (slumpmässigt tal) över dockad UART till ID-kortet
4. ID-kortet beräknar HMAC-SHA256(nyckel, nonce) och returnerar resultatet
5. DEN verifierar HMAC och uppdaterar status på e-Paper-display

## Repositoriestruktur

```
yh-lora-auth-projektarbete/
├── plc/              # Pico 2 + Core1262 firmware (Arduino-pico)
├── id-kort/          # Feather RP2350 + Core1262 + e-Paper firmware
├── key-authority/    # Arduino UNO Q nyckeldistribution
├── docs/             # Teknisk referensdokumentation
├── tests/            # Integrationstester
├── .gitignore
└── README.md
```

## Verktygskedja

- **IDE**: PyCharm 2025.3.2+ med Vibe Code (ACP)
- **PM**: Linear (gratisplan) + Mistral Vibe Work som orkestrator
- **Dokumentation**: Craft (via Craft MCP)
- **Versionshantering**: GitHub (detta repositorie)

## Licens

MIT

---

## SHALLOT CLI (`shallot`)

Lokal Python-CLI för SHALLOT:s automatiska tester, simuleringar och
diagnostik. CLI:t **styr eller verifierar ingen fysisk hårdvara** —
resultat från `test` och `simulate` är automatiska tester respektive
deterministiska simuleringar, inte fysisk hårdvaruverifiering.

### Installation

```bash
python3 -m pip install -e .
shallot --help
shallot          # interaktivt TUI-läge (meny, bekräftar hårdvarunära steg)
```

Kräver Python ≥ 3.9. `pyserial` installeras automatiskt (behövs för
`device list` / `monitor`); `pytest` behövs för `shallot test`.

### Exempel

```bash
# Kör befintliga pytest-sviter (all|protocol|den|paw|mamabear|e2e|fido2)
shallot test den
shallot test fido2
shallot test all --json

# Simulera DEN–PAW challenge-response (alltid märkt SIMULATED / TEST-ONLY)
shallot simulate auth --scenario success
shallot simulate auth --scenario wrong-key   # även: timeout|crc|disconnect|late-ack

# Koda/avkoda UART-ramar: AA | len u16 LE | type | payload | CRC32 LE
shallot protocol encode --type challenge --payload 0001020304050607
shallot protocol decode --frame aa08000100010203040506071cf3b72b

# Simulerad säkerhetsincident för presentation (alltid märkt SIMULERING).
# Börja inzoomad på larmet, zooma sedan ut för avslöjandet. Deterministisk,
# hårdvarufri, ändrar inga verkliga flöden. Exakt kommando:
shallot demo incident

# Lokala förklaringar (offline, ingen extern tjänst). Med --ai utvecklar en
# lokal Ollama-modell ämnet (endast localhost; prompten innehåller bara
# texten ovan, aldrig hemligheter). Kräver `ollama serve` + modell.
shallot explain --list
shallot explain fail-closed
shallot explain break-glass --ai --model llama3.2

# Skrivfri miljökontroll (verktyg, kataloger, portar, osäkra byggen)
shallot doctor

# Visa byggkommando utan att bygga (enda läget som stöds)
shallot build paw --dry-run
shallot build den --dry-run

# Lista serieportar (skrivfritt, osäker identifiering)
shallot device list

# Skrivskyddad visning av serial-loggar (ingen kommandostyrning)
shallot monitor --device den --port /dev/ttyACM0

# Läsande MamaBear-fjärrläge över system-SSH (kräver bekräftelse)
shallot mamabear status --host mamabear
shallot mamabear test --host mamabear --output mamabear-test.json

# FIDO2-härdningsspår (PoC, mock som standard, SIMULATED / TEST-ONLY)
shallot fido2 register --user admin-01
shallot fido2 authenticate --user admin-01
shallot fido2 credential list
shallot fido2 simulate --scenario success
```

Exit-koder: `0` = ok, `1` = fel vid körning/underkända tester,
`2` = felaktig användning.

CLI:ts egna tester (kräver inte hårdvara):

```bash
python3 -m pytest tools/shallot_cli/tests -q
```

### Begränsningar (MVP)

- **LoRa är utanför aktiv MVP** och hanteras inte av CLI:t.
- DEN och PAW har **inget säkert kommando-API**: CLI:t implementerar
  inte `unlock`, automatisk autentisering eller flashning, och
  automatiserar inte provisionering.
- `build` visar endast vilket `compile`-kommando som skulle köras
  (`--dry-run`). Bygge/uppladdning kräver ett framtida explicit
  `--hardware`-läge. Befintliga skript som implicit laddar upp
  (t.ex. `build-uf2.sh pio` → `pio run --target upload`) används aldrig.
- `device list` och `monitor` skriver aldrig till hårdvara; `monitor`
  läser endast loggar och kan inte styra enheten.
- `mamabear status|test` kör endast en hårdkodad allowlist av läsande
  kommandon (`uname`, `uptime`, `free`, `df` resp. ett formstrikt
  självtest). Ingen nyckelgenerering, distribution, provisionering,
  flashning eller annan skrivande åtgärd finns — och godtyckliga
  fjärrkommandon från användarinput körs aldrig.

### MamaBear-fjärrläge (läsande)

MamaBear är en SSH-nod som nås över Tailscale via ditt eget ssh-alias:

```bash
# ~/.ssh/config innehåller t.ex:
#   Host mamabear
#     HostName <tailscale-namn>
#     User <användare>

shallot mamabear status --host mamabear
shallot mamabear test --host mamabear --output mamabear-test.json
```

- **SSH via systemkonfiguration:** CLI:t använder systemets `ssh`-binär
  och aliaset ur `~/.ssh/config` med `BatchMode=yes` (frågar aldrig efter
  lösenord — misslyckas fail-closed i stället). Lösenord, privata
  nycklar, `user@`-former och IP-adresser hanteras aldrig; host keys
  verifieras enligt din egen konfiguration och accepteras aldrig
  automatiskt. `--host 100.64.x.x` avvisas — använd aliaset.
- **Bekräftelse krävs** innan anslutning (`[j/N]`-fråga, eller `--yes`
  för skriptad körning). Utan bekräftelse sker ingen anslutning.
- **Maskering:** nycklar, token, fingerprint, rå payload-hex, privata
  IP-adresser (inkl. Tailscale `100.64/10`) och MAC-adresser maskeras
  innan output visas, sparas eller används vidare (t.ex. mot Ollama).
- **Resultat:** `test` (och `status`) sparar ett tidsstämplat
  JSON-resultat lokalt med kommando, tidpunkt, exit-kod, teststatus och
  sanerad output. Terminalen visar anslutning, status,
  passerat/misslyckat och sökväg till filen.
- **Fail closed:** vid anslutningsfel, timeout eller oväntad output
  skapas ingen skrivning på MamaBear och exit-koden blir `1`.
- **Scope:** resultaten är fysisk status-/självtestverifiering av
  MamaBear-noden — inte bevis för hela DEN–PAW-autentiseringskedjan.

Exempel på resultatfil (`mamabear-test-20260914T100000Z.json`):

```json
{
  "tool": "shallot mamabear test",
  "host_alias": "mamabear",
  "timestamp_utc": "2026-09-14T10:00:00Z",
  "transport": {"via": "system-ssh", "alias_source": "~/.ssh/config",
                "batch_mode": true, "connect_timeout_s": 10,
                "command_timeout_s": 30},
  "commands": [
    {"name": "exec-sanity", "command": "echo MAMABEAR_SELFTEST_OK",
     "exit_code": 0, "timed_out": false, "check": "pass",
     "output": "MAMABEAR_SELFTEST_OK\n", "stderr": ""},
    {"name": "pipe-sanity", "command": "printf 'a\\nb\\n' | wc -l",
     "exit_code": 0, "timed_out": false, "check": "pass",
     "output": "2\n", "stderr": ""},
    {"name": "clock", "command": "date -u +%Y-%m-%dT%H:%M:%SZ",
     "exit_code": 0, "timed_out": false, "check": "pass",
     "output": "2026-09-14T10:00:00Z\n", "stderr": ""}
  ],
  "passed": 3,
  "failed": 0,
  "aborted": false,
  "transport_error": null,
  "teststatus": "pass",
  "exit_code": 0,
  "scope_note": "Fysisk status-/självtestverifiering av MamaBear-noden. Inte bevis för hela DEN–PAW-autentiseringskedjan."
}
```

### FIDO2-härdningsspår (proof of concept)

Kompletterar — ersätter inte — UART/HMAC-autentiseringen mellan PAW
och DEN. **FIDO2 skyddar användar- och adminidentitet** (vem får göra
känsliga administrativa åtgärder, med användarnärvaro);
**UART/HMAC skyddar PAW–DEN-kommunikationen** (att brickan är äkta).
DEN fattar fortsatt lokala fail-closed beslut för PAW–DEN.

```bash
shallot fido2 register --user admin-01          # kräver bekräftelse
shallot fido2 authenticate --user admin-01      # ALLOW/DENY + skäl
shallot fido2 credential list                   # sanerad tabell
shallot fido2 credential status --credential <id>
shallot fido2 credential revoke --credential <id>  # kräver bekräftelse
shallot fido2 credential set-policy --credential <id>  # ändra UV-policy
  --user-verification required                         # (kräver bekräftelse)
shallot fido2 simulate --scenario success       # även: unknown-credential,
  # revoked-credential, wrong-origin, replay, timeout, invalid-signature
```

- **Hotmodell:** angripare med stulen admin-terminal utan
  användarnärvaro nekas (fail closed); stulen/återspelad assertion
  nekas via singelbruk-challenges + timeout; fel origin/RP-ID nekas;
  spärrade credentials nekas. Mock-backenden är INTE ett
  säkerhetsantagande — den övar endast ceremonier; se restrisker i
  `docs/19-fido2-designspec.md`.
- **Användningsfall:** registrering av admin-credentials hos MamaBear
  som auktoritativ källa (Trust Root), assertion-verifiering före
  känsliga åtgärder, livscykel (spärrning med auditpost) och negativa
  tester.
- **Lagring:** endast credential-ID, användar-ID (anonymt, t.ex.
  `admin-01` — aldrig e-post), skapad-tid, status och policy.
  Privata nycklar sparas aldrig. Standardlagring:
  `~/.local/share/shallot/fido2-test/` (testdata); välj annan rot med
  `SHALLOT_FIDO2_STORE` för att separera framtida produktionsdata.
  Varje åtgärd (register/revoke/authenticate) ger en auditpost.
- **Sanering:** all output saneras före visning, loggning och eventuell
  Ollama-analys. Långa credential-ID:n trunkeras (`cred:<8>…<4>`),
  tokens/nycklar/CBOR-payloads, privata adresser och e-post maskeras.
- **Begränsningar:** mock som standard; fysisk authenticator kräver
  explicit `--hardware` (aldrig automatisk åtkomst).
  Resultat är ALLOW/DENY-text — ger aldrig DEN/PAW skrivkommandon.
  Detta är **proof of concept, inte en certifierad
  FIDO2-implementation**.

#### Fysisk authenticator (Pico Fido @ ESP32-S3, `--hardware`)

```bash
pip install "fido2>=1.1"   # CTAP2-klient (Yubicos bibliotek)
shallot fido2 device list                             # 1. syns enheten?
shallot fido2 register --user admin-01 --hardware --yes   # 2. rör vid knappen
shallot fido2 authenticate --user admin-01 --hardware     # 3. ALLOW?
# Kräv PIN/biometri (lagras i policyn, verkställs även utan flagga):
shallot fido2 register --user admin-01 --hardware --yes --require-uv
```

- Flasha Pico Fido via PicoKeys ESP32-flasher, anslut via USB, rör vid
  knappen vid prompt. Stäng webbläsaren under CLI-bruk (exklusiv HID-åtkomst).
- Sätt en PIN på enheten först (nyflashad = ingen PIN): webbläsarens
  säkerhetsnyckel-inställningar (`chrome://settings/securityKeys`).
  CLI:t frågar efter PIN vid behov — tom rad avbryter rent. Gissa aldrig:
  för många fel PIN kan spärra enheten. (PicoKey App är ett betalalternativ,
  29,49 €/enhet — behövs inte här.)
- RP-verifiering: self-attestation (`packed` utan x5c) och `none`
  accepteras explicit; allt annat avvisas. ECDSA P-256 mot lagrad publik
  nyckel + monoton sign-counter (klondetektion: regression = DENY).
- Mock- och HW-credentials samsas i lagringen (fältet `backend`);
  fel läge mot en credential ger `DENY (wrong-backend)`.
- Rekommendation: aktivera Secure Boot + OTP på ESP32-S3 mot
  flash-dumpar vid stöld; se `docs/19-fido2-designspec.md`.
  Pico Fido är AGPL-3.0 — stock-firmware för internt bruk är oproblematiskt;
  distribuera inga modifierade byggen utan att pröva licensplikten.

#### Godkänna admin-credential hos MamaBear (manuell procedur)

CLI:ts `mamabear`-läge är läsande av design och MPU-skriptet har inget
credential-begrepp — därför finns ännu ingen automatisk överföring.
Godkännande sker manuellt, med endast publik metadata:

```bash
# 1. Exportera (aldrig hemligheter — privat nyckel lämnar inte enheten)
shallot fido2 credential export --credential <id> --output admin-01.approval.json
# → skriver fil + visar fingeravtryck, t.ex. fingeravtryck 9f3ac21be04d77aa

# 2. Räkna om fingeravtrycket ur filen (ska matcha raden ovan):
python3 -c "import hashlib,json; d=json.load(open('admin-01.approval.json')); print(hashlib.sha256((d['credential_id']+'|'+(d['public_key'] or '')).encode()).hexdigest()[:16])"

# 3. Kopiera till MamaBear över befintlig Tailscale-SSH (samma alias som mamabear-läget).
#    OBS: aliaset måste sätta rätt fjärranvändare — CLI:t kör `ssh <alias>` utan
#    user@-prefix (medvetet, aldrig adresser i CLI). Kräv i ~/.ssh/config:
#      Host mamabear
#        HostName <mamaBear.tail....ts.net>
#        User user
scp admin-01.approval.json <alias>:/home/user/shallot/admin-credentials/approved/

# 4. På MamaBear: verifiera fingeravtrycket mot det som lästes upp via
#    andra kanalen, lägg sedan en auditpost i en separat logg:
ssh <alias> "mkdir -p /home/user/shallot/admin-credentials/approved /home/user/shallot/audit"
# (flytta filen på plats vid behov, verifiera, appenda JSONL-post med ts/action/fingerprint)
```

Detta är bokföring, ännu ej verkställighet: inget i dagens system
konsulterar MamaBears godkännanden vid autentisering. Ett framtida
`mamabear approve`-flöde (MamaBear countersignerar med sin
Ed25519-nyckel, samma mönster som blocklist-signering) är specificerat
som nästa steg i `docs/19-fido2-designspec.md`.

### Kända specifikationskonflikter

1. **Nonce-längd:** `docs/01-kravspecifikation.md` (FR-CR-001),
   `docs/02-arkitektur.md` och `plc/den-main/README.md` anger
   128 bitar / 16 byte, medan `docs/11-dockat-uart-protokoll.md`,
   firmwaren (`DEN_NONCE_LEN 8`) och pytest-sviten använder
   64 bitar / 8 byte. **CLI:t och firmwaren använder 8 byte.**
2. **HMAC-indata:** `docs/11-dockat-uart-protokoll.md` §3 anger
   `HMAC-SHA256(K, epoch || nonce)` för RESPONSE, medan firmwaren
   och testerna beräknar `HMAC-SHA256(K_mac, nonce)` med härledd
   nyckel `K_mac = SHA-256(master || "MAC")[:16]` och utan epoch.
   Epoch-bindning finns endast i provisioneringsprotokollet
   (`docs/12-envelope-protocol.md`, `docs/14-provisioning-v2-design.md`),
   inte i den dockade autentiseringen. **CLI:t simulerar
   `HMAC(K_mac, nonce)`, dvs. firmware-beteendet.**
