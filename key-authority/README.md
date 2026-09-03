# Key Authority (Arduino UNO Q)

Firmware for nyckeldistribution: Arduino UNO Q (Qualcomm QRB2210 + STM32U585).

## Ansvar

- Generera AES-128-nycklar med STM32U585 hardware TRNG
- Distribuera nycklar via UART till bada noder (PLC och ID-kort)
- Säker nyckellagring pa STM32U585
- **Single Source of Truth**: UNO Q genererar och distribuerar nycklar utan host-datorinvolvering

## Arkitektur

UNO Q har en dubbelprocessorarkitektur:
- **Qualcomm QRB2210** (MPU, Debian Linux): orchestreringsgränssnitt via Arduino App Lab (hanterar aldrig nyckelmaterial)
- **STM32U585** (MCU): säker nyckelgenerering med hardware TRNG, nyckellagring och UART-distribution

## Flode

1. UNO Q genererar en AES-128-nyckel med STM32U585 hardware TRNG (kryptografiskt säker)
2. Nyckeln distribueras till båda noder via UART efter fysisk bekräftelse
3. Nyckeln lagras säkert på STM32U585 och aldrig exponeras för MPU
4. **Air-gap**: Allt fungerar helt utan anslutning till host-dator
