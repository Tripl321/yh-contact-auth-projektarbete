# UNO Q — tyst Bridge efter flash: fynd från dokumentsökning

Datum: 2026-09-24 · Status: **LEANDE HYPOTES, inte domslut** — tidsstämplad bänkevidens saknas; AGENTS.md "Verifiera istället för att anta" gäller för nästa steg.
Beslut 2026-09-24: **parkerad** till efter videogenomgång — fjärrspår (SWD/PC-sampling) läggs ner; nästa steg är fysisk USB-konsol.

## Symptom att förklara

Efter flash: total tystnad från UNO Q — inga RPC-registreringar, ingen konsol, timeouts mot Bridge.

## Fynd

### 1. Bridge.begin() blockerar i väntan på routern [dokumenterat, länk ej säkrad]

Bridge-bibliotekets `begin()` skickar RESET_METHOD och väntar på svar från Linux-sidan; uteblir svar hänger den. Kända felrapporter i Arduino-forum: "stuck waiting forever for a mutex", krascher när Linux-sidan inte är redo, versionsbundna Bridge-buggar (vissa kärnversioner trasiga, andra fixade).

Källa: forumtrådar som citerar Bridge-källkod. URL:er ej säkrade — se "Källor" nedan.

### 2. Vår firmware anropar Bridge ovillkorligt, före all konsoloutput [VERIFIERAD I REPO]

`setup()` anropar `setupBridgeRPC()` ovillkorligt (`key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino:567`), vars första rad är `Bridge.begin()` (`.ino:490`). Boot-bannern (`.ino:571-574`) och `loop()` nås först därefter. Fastnar `begin()`-handskakningen: ingen bänner, ingen loop, inga RPC-registreringar, ingen konsol. Matchar samtliga observationer.

### 3. Pin-frågan löst vid sidan av [dokumenterat + repo-konsistent]

MCU-sidan av Bridge kör Serial2 (LPUART1, intern); Serial1 = USART1 = D0/D1-headerpinnar (experimentellt belagt i forum). Vår nyckeldistribution via Serial1 (`distributeKey` `.ino:243`, transport `.ino:217-300`, `Serial1.begin` `.ino:562`) krockar inte med bryggan. `docs/15 §2`:s kabeldragning är pinnmässigt korrekt.

## Kvarstående osäkerhet — en fråga, två kandidater

- **A (troligast): fast i begin()-handskakning** — stöds av forumrapporter + det ovillkorliga anropet (fynd 1+2).
- **B (mindre trolig): krasch-loop** — kräver konsol/GDB för att utesluta.

Båda avgörs på sekunder med USB-konsol (bootlogg syns direkt). Fjärrvägen (SWD-bitbang → PC-sampling mot ELF) är fel verktyg för denna fråga.

## Nästa steg (fysiska, post-video)

1. USB-konsol till UNO Q → se var den står. Bänner synlig = inte fast i begin() → kandidat B.
2. Utfall A: non-blocking Bridge-init (liten firmware-fix).
3. Utall A + versionsfråga uppströms: installerad UNO Q-kärna 0.8.2 (senast kända 0.9.0), Bridge 0.0.7 (senast kända 0.0.8) — kontrollera om känd Bridge-bugg är fixad i 0.9.0/0.0.8 innan egen patch.

## Källor

- **Repo (verifierade 2026-09-24):** `key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino` rader 217-300, 489-490, 560-578.
- **Dokumentsökning:** forumtrådar + citerad Bridge-källkod. URL:er ej säkrade — bakgrundsagenten avbröts innan länkfil skrevs. Innan domslut på fynd 1 och 3: säkra primärkällorna (Arduino-forum, Bridge-lib-källkod på GitHub) och komplettera här.

## Upplösning 2026-09-26 (SWD + router-loggar + RPC, ingen USB-konsol behövdes)

**Ingen av kandidaterna stämde.** Verklig orsakskedja (allt verifierat):

1. Sketchen flashades med brädans `arduino-flash` till **0x080F0000** — men 1.0.0-kärnan läser sketch (`user_sketch`) från **0x08100000**. Fel adress + fel format (rå ELF istället för zsk-container) → kärnan hittade ingen giltig sketch → idle i `arch_cpu_idle` (3× identisk PC, inga faults). "Tystnaden" var alltså: ingen sketch körde alls.
2. Mamabear ÄR UNO Q:ns Linux-sida (`Machine model: Arduino UnoQ`, Debian 13). Dess USB visar bara interna hubbar + DEN/PAW — MCU:ns USB når aldrig hit. USB-konsol var fel spår från början.
3. Rättelse: bygg zsk på Mac (`arduino-cli`, `NO_ED25519` pga RNG.cpp-kollision, `boot_mode=immediate`), flasha till **0x08100000** via SWD med kanoniska `flash_sketch.cfg`, mailbox-reboot. Domslut via SWD: boot → `llext_load` rc=0 → `bootstrap(main)` → `Bridge.begin(115200)` (this+baud verifierade) → **return TRUE** → loop kör (mon/connected-poll ~1/s i router-loggen).
4. Kvar: routern (0.9.0) svarar `$/reset`/`$/version`/`$/register` men sketch-metoder syns ändå inte; `mon/connected=false` permanent (ingen gadget-värd). `Bridge.begin()` + provides behöver retry-tålighet → implementerat i sketch (`bringUpBridge()` + 10 s retry + 60 s re-registration, LED-ack vid länk-up).
5. Verifierat fungerande: RPC `get_key_state`→0, `request_key_generation`→true, state→1, `get_key_fingerprint`→hash. LED-ack + bryggåterhämtning efter router-omstart delvis verifierad (återstår: orphan efter manuell router-omstart behöver MCU-reboot — dokumenterad begränsning, ej åtgärdad).
6. Kvar att göra: knapp-initierad ceremoni utan konsol/RPC (designbeslut — knappen idag endast confirm), ev. router-uppdatering (versionsfrågan kvarstår: finns nyare arduino-router med full handshake?).
