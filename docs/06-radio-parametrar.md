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

## Duty cycle-policy och sändningsbudget

Detta är ett bindande krav för alla implementationer, tester och driftsättningar i detta repo. Se `AGENTS.md` ("Obligatoriskt krav: LoRa duty cycle och radiosäker drift") för den övergripande kravspecifikationen.

### Regulatorisk bakgrund

ETSI EN 300 220 tillåter maximalt 1 % duty cycle i EU ISM-bandet (868,0–868,6 MHz) om ingen Listen-Before-Talk (LBT) implementeras. Detta motsvarar maximalt 36 sekunders sammanlagd sändtid per rullande 60-minutersfönster.

SHALLOT:s nuvarande implementation saknar LBT. Därför gäller följande designbudget:

| Parameter | Värde |
| -- | -- |
| Duty cycle-budget | 1 % |
| Max sändtid per rullande 60 min | 36 sekunder (36 000 ms) |
| Fönstertyp | Rullande, glidande 60 minuter |
| LBT implementerad | Nej |

### Vad som räknas in i budgeten

Alla sändningar över LoRa räknas in i sändningsbudgeten, oavsett meddelandetyp:

- Autentiseringspaket (CHALLENGE, RESPONSE, SUCCESS, FAILURE)
- Returer (omlagring av CHALLENGE eller RESPONSE vid timeout)
- Heartbeat-paket (HEARTBEAT, om implementerad)
- Test- och felsökningssändningar

### Beräknad time-on-air per pakettyp

Time-on-air (ToA) beräknas med Semtechs formel (AN1200.13) för konfigurerade parametrar: SF7, BW125 kHz, CR4/5, explicit header, CRC aktiverad, 8-symbolers preamble.

T_symbol = 2^SF / BW = 2^7 / 125 000 = 1,024 ms

| Pakettyp | Storlek (byte) | ToA (ms) |
| -- | -- | -- |
| CHALLENGE | 29 | 66,8 |
| RESPONSE | 37 | 82,2 |
| SUCCESS | 29 | 66,8 |
| FAILURE | 29 | 66,8 |
| HEARTBEAT | 33 | 71,9 |

### Konsekvens för autentiseringscykler

En fullständig autentiseringscykel (CHALLENGE + RESPONSE + SUCCESS) utan returer förbrukar cirka 216 ms sändtid. Med tre returer per paket (worst case) stiger förbrukningen till cirka 514 ms.

| Scenario | ToA per cykel (ms) | Max cykler per timme |
| -- | -- | -- |
| Utan returer | 216 | 166 |
| Worst case (3 returer CHALLENGE + 3 returer RESPONSE) | 514 | 70 |

Kontinuerlig polling med 10 sekunders intervall (360 cykler/timme) skulle förbruka cirka 78 sekunder sändtid och därmed överskrida budgeten med mer än en faktor två. SHALLOT bör därför vara händelsestyrt, inte pollande.

## Implementeringskrav för sändningsbudget

Följande krav ska implementeras i edge enforcement-nod och PAW för att säkerställa efterlevnad av duty cycle-budgeten.

### 1. Beräkna time-on-air före varje sändning

Innan ett paket sänds ska faktisk LoRa time-on-air beräknas baserat på paketets storlek och konfigurerade radioparametrar (SF7, BW125, CR4/5). Beräkningen ska använda Semtechs formel (AN1200.13) eller en förkalkylerad uppslagstabell för de standardiserade paketstorlekarna.

### 2. Bokför sändtid i rullande fönster

En sändningsbudgetregulator ska bokföra sammanlagd sändtid i ett rullande 60-minutersfönster. För varje sändning registreras ToA och tidstämpel. Summan av all sändtid inom det senaste 60 minuterna ska inte överstiga 36 000 ms.

### 3. Köa, fördröj eller undertryck vid full budget

När budgeten är uttömd ska icke-kritiska paket köas eller fördröjas tills budget frigörs. Autentiseringspaket (CHALLENGE, RESPONSE) är kritiska och får sändas om budget medger. Heartbeat och testpaket är icke-kritiska och ska undertryckas när budgeten är slut.

### 4. Returer belastar samma budget

Alla returer ska belasta samma sändningsbudget som ursprungliga sändningen. Returer ska ha exponentiell backoff mellan försök för att sprida sändningar över tid och minska risk för budgetötning. Backoff rekommendation: 1 s, 2 s, 4 s (exponentiell) mellan försök, varav total cykel inklusive returer maximalt förbrukar cirka 514 ms sändtid.

### 5. Heartbeat begränsas utanför aktiv session

HEARTBEAT-paket ska vara avställda om ingen aktiv autentiseringssession eller testning pågår. Om heartbeat aktiveras ska sändningsfrekvensen dimensioneras så att den inte förbrukar mer än 10 % av sändningsbudgeten (maximalt 3,6 sekunder per timme), vilket motsvarar högst 50 heartbeat-paket per timme vid 71,9 ms per paket.

## Regulatorisk kontrollpunkt

### Nuvarande konfiguration

| Parameter | Värde | Status |
| -- | -- | -- |
| Frekvens | 868,1 MHz | Inom EU ISM-band (868,0–868,6 MHz) |
| Sändeffekt (konfigurerad) | 20 dBm | Ej verifierad |
| Duty cycle-gräns | 1 % (36 s/timme) | Designbudget, ej verifierad |
| LBT | Ej implementerad |  |

### Verifiering före fälttest och driftsättning

Följande måste verifieras innan efterlevnad kan hävdas:

1. **Effektiv utstrålad effekt (ERP):** Mät faktisk ERP inklusive antennförstärkning och kabelförluster. Konfigurerad 20 dBm är modulens TX-power, inte systemets ERP. Faktisk ERP kan avvika beroende på antenn, kabel, kopplingsdämpning och PCB-layout.

2. **Antenn och kablage:** Dokumentera antennförstärkning (dBi), kabellängd, kabeltyp och uppskattad kabeldämpning. Beräkna system-ERP: TX-power + antennförstärkning - kabel- och kopplingsförluster.

3. **Duty cycle-mätning:** Verifiera i fälttest att sammanlagd sändtid per rullande 60 minuter inte överskrider 36 sekunder under förväntade driftscenarier.

4. **Frekvensnoggrannhet:** Verifiera att modulen sänder inom 868,1 MHz med tillräcklig noggrannhet för att inte överskrida bandgränserna (868,0–868,6 MHz).

Efterlevnad av ETSI EN 300 220 får inte presenteras som uppmätt eller garanterad om inte ovanstående punkter har verifierats mätningstekniskt. Nuvarande dokumentation avser designmål, inte certifierade resultat.

## Fälttestresultat

Värdena nedan fylls i efter fälttestning som del av PRO-77.

| Mätvärde | Målvärde | Uppmätt värde | Status |
| -- | -- | -- | -- |
| Paketleverans | ≥95% | — | Ej mätt |
| Latens (32-byte paket) | ≤2 s | — | Ej mätt |
| Paketförlust (10 min kontinuerlig) | 0% | — | Ej mätt |
| Räckvidd (utomhus, fri sikt) | ≥1 km | — | Ej mätt |
| Interferens (2 andra LoRa-enheter, samma kanal) | Fungerar | — | Ej mätt |
| System-ERP | ≤20 dBm | — | Ej mätt |
| Sammanlagd sändtid (60 min, normal drift) | ≤36 s | — | Ej mätt |

## Planerade testmetoder

1. **Paketleveranstest:** Skicka 1 000 paket och mät framgångsprocenten.
2. **Latensmätning:** Mät tiden från sändning till bekräftelse för paket på 32 byte.
3. **Räckviddstest:** Testa utomhus med fri sikt och öka avståndet gradvis.
4. **Interferenstest:** Kör två andra LoRa-enheter på samma kanal.
5. **ERP-mätning:** Mät utstrålad effekt med effektmätare eller spektrum-analysator inklusive antenn och kablage.
6. **Duty cycle-verifiering:** Logga all sändtid under 60 minuter av normal drift och verifiera att summan understiger 36 sekunder.