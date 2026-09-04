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
