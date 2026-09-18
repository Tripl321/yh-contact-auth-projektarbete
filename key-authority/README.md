# Key Authority (Arduino UNO Q)

Firmware for nyckeldistribution: Arduino UNO Q (Qualcomm QRB2210 + STM32U585).

## Ansvar

- Generera AES-128-nycklar med STM32U585 hardware TRNG
- Distribuera nycklar via USB till bada noder (PLC och ID-kort)
- Säker nyckellagring pa STM32U585
- **Single Source of Truth**: UNO Q genererar och distribuerar nycklar utan host-datorinvolvering

> **Viktigt 2026-09-04:** Nyckeldistribution sker via **USB** (USB CDC). Tidigare UART-beskrivning (Serial1, D0/D1) är föråldrad och ska inte användas. Alla enheter ansluts via USB-hubb till host/Mama Bear MPU.

## Arkitektur

UNO Q har en dubbelprocessorarkitektur:
- **Qualcomm QRB2210** (MPU, Debian Linux): orchestreringsgränssnitt via Arduino App Lab (hanterar aldrig nyckelmaterial), USB-värd för distribution
- **STM32U585** (MCU): säker nyckelgenerering med hardware TRNG, nyckellagring och nyckelhantering (distribueras via USB från MPU/host)

## Flode

1. UNO Q genererar en AES-128-nyckel med STM32U585 hardware TRNG (kryptografiskt säker)
2. Nyckeln distribueras till båda noder via USB efter fysisk bekräftelse
3. Nyckeln lagras säkert på STM32U585 och aldrig exponeras i klartext utanför säker domän
4. **Air-gap**: Allt fungerar helt utan anslutning till host-dator (Mama Bear MPU agerar USB-värd)

## USB-provisionering i drift (MPU-relä)

MCU:ns distributionsväg är USB CDC (`Serial`). Enheterna når MCU:ns
arbitrerrouter-uttag via ett MPU-sida relä som kopierar ramar byte-för-byte mellan
MCU:s övervakningsuttag (`127.0.0.1:7500`) och enheternas `/dev/ttyACM`-portar:

    python3 scripts/usb_provisioning_relay.py

Reläet filtrerar endast icke-hemlig debug (`<0x80`), routar ramar utan target
(KEY_DATA) till den pågående utväxlingens enhet och återöppnar enheter via
deras stabila `by-id`-sökväg vid EIO. Det deltar inte i nyckelhanteringen;
audit bärs endast av fingerprint-taggar (`0xA4` STORED, `0xA6` COMMIT).

Verifierat på bänken (epok 1 och 2): PLC och PAW lagrar identiska nycklar,
MCU gör konstant-tids hashverifiering mot pending-hash och distributionen
fails closed vid CRC-mismatch/tidsutgång utan att lagra del-nyckel. Enda
sändarväg är USB; Serial1-UART-sändaren är borttagen (ingen dubbel sändare).
