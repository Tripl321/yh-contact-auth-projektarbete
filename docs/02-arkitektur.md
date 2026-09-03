# Systemarkitektur — SHALLOT

> Status: Ej paabörjad | Vecka: 1 | Linear: PRO-31

## 1. Oeversikt

Systemet bestaar av tre noder:

| Nod | Haardvara | Roll |
|-----|---------|------|
| PAW (Portable Authentication Wearable) | Adafruit Feather RP2350 + Core1262 + e-Paper | Baerbar ID-bricka, skickar autentiseringsbegaran |
| Edge enforcement-nod | Raspberry Pi Pico 2 (RP2350A) + Core1262 | Verifierar autentisering, fattar fail-closed-beslut |
| Air-gapped provisioneringshubb (Mama Bear) | Arduino UNO Q | Genererar och distribuerar AES-128-nycklar via UART (single source of truth) |

## 2. Databussdiagram

(Ej ritat an — Mermaid-diagram tillkommer)

## 3. Kommunikation

- LoRa P2P, 868 MHz
- Beacon: 13 bytes plaintext (node_id + timestamp + nonce)
- Auth request: 41 bytes signerad (badge_id + nonce + HMAC)
- RSSI-gating: >-40 dBm on-site, <-70 dBm fail-closed

## 4. Fail-closed-princip

Relay OFF som standard. Autentisering kraevs foer att slaa paa. Trigger foer OFF:
- Heartbeat-timeout > 5 s
- Svag RSSI (< -70 dBm)
- Ogiltig signatur
- Replay-detektering
- Utgaangen epoch-nyckel
