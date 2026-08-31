# YH LoRa Auth Projektarbete

## Projektbeskrivning

Challenge-response autentisering över LoRa P2P med AES-128 och HMAC-SHA256.

Ett IoT-säkerhetsprojekt som demonstrerar kryptografisk autentisering mellan
två noder över LoRa-radio. En PLC (Raspberry Pi Pico 2) utmanar ett ID-kort
(Adafruit Feather RP2350) med en nonce. ID-kortet svarar med
HMAC-SHA256(AES-128-nyckel, nonce). Status visas på en e-Paper-display.

## Arkitektur

- **PLC**: Raspberry Pi Pico 2 (RP2350A) + Waveshare Core1262-868M (SX1262 LoRa)
- **ID-kort**: Adafruit Feather RP2350 + Core1262-868M + 1.54" Waveshare e-Paper
- **Key Authority**: Arduino UNO Q (Qualcomm QRB2210 + STM32U585) -- genererar AES-128-nycklar, distribuerar via USB till bada noder

## Kryptografiskt flode

1. UNO Q genererar en AES-128-nyckel
2. Nyckeln distribueras via USB till bada noder (PLC och ID-kort)
3. PLC skickar en nonce (slumpmässigt tal) over LoRa till ID-kortet
4. ID-kortet beräknar HMAC-SHA256(nyckel, nonce) och returnerar resultatet
5. PLC verifierar HMAC och uppdaterar status på e-Paper-display

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
