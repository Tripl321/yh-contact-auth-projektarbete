# Kravspecifikation - SHALLOT

## 1. Inledning

### 1.1 Syfte
Detta dokument definierar funktionella och icke-funktionella krav för SHALLOT-systemet, ett säkert ID-bricka (badge) autentiseringsystem med LoRa P2P-kommunikation och HMAC-SHA256 utmanings-svarsautentisering.

### 1.2 Omfattning
SHALLOT-systemet består av tre hårdvaruenheter:
- UNO Q: Air-gapped nyckeldistributionshub
- Edge enforcement-nod (PLC): Raspberry Pi Pico 2 + Core1262 (SX1262 LoRa)
- PAW (ID-bricka): Adafruit Feather RP2350 + Core1262 + e-Paper display

### 1.3 Definitioner
- Air-gapped: Fysiskt isolerad från nätverk
- Fail-closed: Systemet nekar åtkomst vid fel eller timeout
- HMAC-SHA256: Hash-based Message Authentication Code
- LoRa P2P: Point-to-point kommunikation via LoRa-radio

---

## 2. Funktionella Krav

### 2.1 Autentisering

| ID | Krav | Prioritet |
|----|------|-----------|
| FR-001 | Systemet skall autentisera användare via HMAC-SHA256 utmanings-svarsprotokoll | Must |
| FR-002 | Edge enforcement-nod skall generera 128-bit cryptographically secure nonce | Must |
| FR-003 | PAW skall beräkna HMAC-SHA256 svar på mottagen nonce | Must |
| FR-004 | Edge enforcement-nod skall verifiera HMAC-svar | Must |
| FR-005 | Systemet skall implementera fail-closed princip vid autentiseringsfel | Must |

### 2.2 Nyckelhantering

| ID | Krav | Prioritet |
|----|------|-----------|
| FR-010 | UNO Q skall generera AES-128 nycklar via STM32U585 TRNG | Must |
| FR-011 | Nycklar skall distribueras via USB till edge enforcement-nod | Must |
| FR-012 | Nycklar skall distribueras via USB till PAW | Must |
| FR-013 | Nycklar skall lagras säkert i enhetens minne | Must |
| FR-014 | Nyckeldistribution kräver fysisk bekräftelse (knapptryck) | Must |

### 2.3 Kommunikation

| ID | Krav | Prioritet |
|----|------|-----------|
| FR-020 | Edge enforcement-nod och PAW skall kommunicera via LoRa P2P | Must |
| FR-021 | Systemet skall använda frekvens 868.1 MHz (EU ISM-band) | Must |