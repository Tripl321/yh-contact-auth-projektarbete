# 08 — Hotmodellering

## Omfattning

Hotmodellen beskriver säkerhetsrisker i SHALLOT:s autentiserings- och nyckelhanteringsflöde. Den kontaktbaserade UART-länken är den primära autentiseringstransporten. LoRa behandlas endast som separat larm- och framtidsspår.

## Replay-attack

Den ursprungliga lösningen saknade sekvensnummer och byggde enbart på en slumpmässig nonce. Ett inspelat giltigt paket kunde därför återanvändas om mottagaren saknade nonce-historik.

**Mitigering:** Det reviderade protokollet använder ett strikt ökande 32-bitars sekvensnummer per sändar-ID. Mottagaren förkastar paket med samma eller lägre sekvensnummer. Challenge-response över UART använder dessutom en färsk nonce per session och fail-closed-verifiering.

**Restrisk:** Efter omstart återställs sekvensnumret. Återspelning kan då vara möjlig om mottagaren inte sparar sekvensnumret icke-flyktigt. Framtida åtgärd är lagring i flash/EEPROM eller en boot-counter kombinerad med sekvensnummer.

## Meddelandetypsmanipulation

Om Version och Message Type inte täcks av HMAC kan en angripare ändra dem utan att signaturen blir ogiltig. Det kan leda till state confusion, denial of service eller versionsnedgradering.

**Mitigering:** Version och Message Type ingår i HMAC-beräkningen i det reviderade protokollformatet.

## STRIDE

| Hot | Risk | Mitigering | Restrisk |
|---|---|---|---|
| Spoofing | Förfalskat SenderID | HMAC täcker SenderID | Förutsätter skydd av nyckelmaterial |
| Tampering | Manipulerad payload | AES-CTR och HMAC | Korrekt nyckelhantering krävs |
| Repudiation | Förnekad sändning | Audit-logg på UNO Q MPU | Loggtillgänglighet måste verifieras på hårdvara |
| Information Disclosure | Avlyssnad radiotrafik | AES-CTR-kryptering | Trafikanalys och sändarlokalisering kvarstår |
| Denial of Service | Störning eller felaktiga ramar | Retry-policy och fail-closed watchdog | RF-störning kan inte helt förhindras |
| Elevation of Privilege | Åtkomst till nyckelmaterial | Air-gapped UNO Q och fysisk operatörsbekräftelse | Fysisk nyckelhantering kräver verifiering |

## Nyckelåteranvändning

Den ursprungliga designen använde samma AES-128-nyckel för AES-CTR och HMAC-SHA256. Detta är dålig praxis.

**Mitigering:** `K_enc` och `K_mac` härleds separat från master-nyckeln med SHA-256. HMAC använder endast `K_mac`.

## AES-CCM som framtida härdning

AES-CCM kan kombinera kryptering och autentisering i en AEAD-mod och eliminera behovet av separat HMAC och nyckelhärledning. Det är en rekommenderad post-MVP-förbättring och ingår inte i MVP.

## Verifieringsstatus

Protokoll- och fail-closed-beteende täcks av mjukvarutester. Fysisk verifiering av UNO Q RNG, USB-distribution, operatörsbekräftelse och signalintegritet återstår.
