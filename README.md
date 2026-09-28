# SHALLOT

SHALLOT är ett OT-säkerhetsprojekt för autentisering mellan ett ID-kort (**PAW**) och en edgeenhet (**DEN**).

Den aktiva MVP-arkitekturen använder fysisk dockning via USB-C och seriell kommunikation (UART). LoRa finns kvar i repot som äldre och framtida spår, bland annat för OTA och en enkelriktad larmkanal, men är inte den primära transporten i nuläget.

## Säkerhet

Autentiseringen bygger på challenge-response med bland annat:

- HMAC-SHA256
- Nonce för att motverka replay-attacker
- Fail-closed-logik
- CRC-baserat protokollskydd

Nyckelhantering och provisionering hanteras av **Mama Bear**. Äldre kod och dokumentation kan fortfarande referera till namnet UNO Q.

## Hårdvara

- **DEN** – Raspberry Pi Pico 2/RP2350 med Core1262
- **PAW** – Adafruit Feather RP2350 med Core1262 och Waveshare e-Paper
- **Mama Bear** – ansvarar för nyckelgenerering och provisionering

## Struktur

```text
plc/                Firmware för DEN samt äldre LoRa- och nyckelspår
id-kort/            Firmware för PAW, e-Paper och hårdvarutester
key-authority/      Kod för Mama Bear och äldre UNO Q-relaterade delar
shared/             Gemensamt UART-protokoll
libraries/          Delade bibliotek, exempelvis DenUartProtocol och Ed25519
tools/shallot_cli/  Python-CLI för test, simulering och diagnostik
tests/              Protokoll-, säkerhets- och integrationstester
docs/               Krav, arkitektur, protokoll och säkerhetsdesign
