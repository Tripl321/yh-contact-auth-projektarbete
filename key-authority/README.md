# Key Authority (Arduino UNO Q)

Firmware for nyckeldistribution: Arduino UNO Q (Qualcomm QRB2210 + STM32U585).

## Ansvar

- Generera AES-128-nycklar
- Distribuera nycklar via USB till bada noder (PLC och ID-kort)
- Säker nyckellagring pa STM32U585

## Arkitektur

UNO Q har en dubbelprocessorarkitektur:
- **Qualcomm QRB2210** (MPU, Debian Linux): nyckelgenerering via Arduino App Lab
- **STM32U585** (MCU): säker nyckellagring och USB-kommunikation via Arduino IDE

## Flode

1. UNO Q genererar en AES-128-nyckel med kryptografiskt säker slumptalsgenerator
2. Nyckeln skrivs till bada noder via USB
3. Nyckeln lagras säkert pa STM32U585
