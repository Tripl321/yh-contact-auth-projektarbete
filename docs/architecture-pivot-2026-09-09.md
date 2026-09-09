# Architecture Pivot — 2026-09-09

## Beslut

Primär autentiseringstransport för SHALLOT ändras från LoRa P2P till kontaktbaserad dockning (pogo-pins eller USB-C). LoRa behålls i två nya roller.

## Bakgrund

LoRa P2P som autentiseringstransport medför två problem:

1. **Regulatorisk begränsning:** ETSI EN 300 220-2 V3.2.1 begränsar duty cycle till 1% i 868 MHz band M (868,0–868,6 MHz). Detta sätter ett tak på antal autentiseringar per tidsenhet.

2. **Säkerhetsposition:** Radioexponering skapar en attackyta som inte är förenlig med air-gapped-filosofin. En angripare kan avlyssna, störa (jamming) och potentiellt injicera kommandon över radio.

## Ny arkitektur — två distributionsvarianter

### Standardvarianten (kontaktbaserad)

- PAW dockas fysiskt till DEN via pogo-pins eller USB-C
- Challenge-response sker över UART (Serial1)
- Ingen radioemission under autentisering — starkast säkerhetsposition
- Används där tekniker kan nå DEN (tillgänglig installation)

### SHALLOT Over the Air (LoRa)

- PAW autentiseras över LoRa P2P — samma kryptologik, annan transport
- Används där fysisk åtkomst är omöjlig (mast, fasad, tak)
- Hotbilden är annorlunda: angripare som når en mastmonterad DEN har redan en svårare fysisk barriär, vilket kompenserar för den svagare transportsäkerheten

### LoRa TX-only larmkanal (båda varianterna)

- DEN sänder LoRa TX-only som larm- och heartbeat-kanal
- Cover traffic: schemalagda sändningar var 10:e sekund (ca 0,6% duty cycle)
- Heartbeat och larm har identiskt krypterat format — angripare kan inte skilja
- TX-only eliminerar kommandoinjektion (ingen radiovej in)
- Kvarstående risk: sändare kan lokaliseras (RF direction finding)
- DEN är nätansluten — ingen strömbudget för cover traffic

## Vad påverkas inte

Kryptologiken är helt transport-oberoende:

- Nyckelgenerering på Mama Bear (STM32U585 TRNG) — oförändrat
- Nyckeldistribution via USB-C genom USB-hub till PAW och DEN — oförändrat
- HMAC-SHA256 på båda enheter — oförändrat
- Nonce-generering på DEN — oförändrat
- Fail-closed watchdog — oförändrat
- E-Paper statusvisning — oförändrad

## Namnbyten

- UNO Q → Mama Bear (2026-09-09)
- Nyckeldistribution: UART (Serial1 D0/D1) → USB-C via USB-hub

## Linear-referenser

- PRO-87: Definiera kontaktbaserat protokoll för PAW och DEN-dockning
- PRO-88: Implementera UART TX på DEN
- PRO-84: Implementera UART RX på PAW
- PRO-85: Design och montering av pogo-pin-docka
- PRO-86: LoRa TX-only larmkanal med cover traffic
- PRO-83: Uppdatera arkitekturdokumentation med tvåvariant-struktur
- PRO-52: Challenge-response-protokoll (dual transport)
- PRO-53: Autentiseringsbeslut med fail-closed watchdog (transport-oberoende)
