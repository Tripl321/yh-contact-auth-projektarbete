# Radio-parametrar

## Konfigurerade parametrar

Dessa parametrar är konfigurerade och beslutade enligt PRO-78.

| Parameter | Värde | Kommentar |
| -- | -- | -- |
| Frekvens | 868.1 MHz | EU ISM-band |
| Bandbredd | 125 kHz |  |
| Spreading Factor | 7 |  |
| Coding Rate | 4/5 |  |
| Sändeffekt | 20 dBm |  |
| Sync Word | 0x12 | Privat användning, inte LoRaWAN-standard |
| Timeout | 5000 ms |  |
| Omsändningspolicy | 3 försök |  |

## Fälttestresultat

Värdena nedan fylls i efter fälttestning som del av PRO-77.

| Mätvärde | Målvärde | Uppmätt värde | Status |
| -- | -- | -- | -- |
| Paketleverans | ≥95% | — | Ej mätt |
| Latens (32-byte paket) | ≤2 s | — | Ej mätt |
| Paketförlust (10 min kontinuerlig) | 0% | — | Ej mätt |
| Räckvidd (utomhus, fri sikt) | ≥1 km | — | Ej mätt |
| Interferens (2 andra LoRa-enheter, samma kanal) | Fungerar | — | Ej mätt |

## Planerade testmetoder

1. **Paketleveranstest:** Skicka 1 000 paket och mät framgångsprocenten.
2. **Latensmätning:** Mät tiden från sändning till bekräftelse för paket på 32 byte.
3. **Räckviddstest:** Testa utomhus med fri sikt och öka avståndet gradvis.
4. **Interferenstest:** Kör två andra LoRa-enheter på samma kanal.
