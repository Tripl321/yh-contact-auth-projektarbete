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
2. MPU armerar via Bridge; operatören bekräftar med fysisk UNO Q-knapp
3. MCU frigör nyckeln exakt en gång (engångsexport, knapp-gated)
4. MPU `UsbCdcDistributor` överför via USB-CDC till nodens `/dev/ttyACM*`
   (handshake/READY/nyckel+CRC/STORED) och verifierar avtrycket
5. MCU flyttar nyckeltillstånd endast vid verifierad bekräftelse
6. Nyckeln lagras säkert pa STM32U585

Legacy MCU Serial1-sändaren är borttagen (PRO-46 USB-C) — exakt en
sändare existerar. MPU hanterar nyckelbyte endast transient under
överföringen (torkas omedelbart, loggas/auditeras aldrig).
