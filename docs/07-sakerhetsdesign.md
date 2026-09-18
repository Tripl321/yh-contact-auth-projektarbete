# 07 — Säkerhetsdesign

## Nyckelhärledning

Master-nyckeln från UNO Q används inte direkt för kryptering eller HMAC. Vid nyckelreception härleds två separata subnycklar:

- `K_enc = SHA-256(master_key || "ENC")[:16]` för AES-CTR-kryptering.
- `K_mac = SHA-256(master_key || "MAC")[:16]` för HMAC-SHA256.

Detta undviker att samma nyckel används för både kryptering och meddelandeautentisering. Härledningen kräver ett SHA-256-anrop per subnyckel vid nyckelreception, och subnycklarna hålls separerade i minnet.

Referenser: [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final), [RFC 3686](https://www.rfc-editor.org/rfc/rfc3686), Berkeley CS161 och Cryptography Stack Exchange.

## IV-omstartsrisken

IV-formatet är `0x00000000 || sequence_number || nonce`: fyra nollbyte, ett sekvensnummer på fyra byte och en nonce på åtta byte. Vid omstart återställs sekvensnumret till noll. Om samma nonce då återkommer vid samma sekvensnummer kan en IV-kollision uppstå.

För MVP:ns hundratals paket är risken låg. Vid långvarig drift bör noncefältet utökas till 96 bitar enligt NIST SP 800-38D. RFC 3686 kräver färska nycklar efter strömavbrott för att undvika IV-återanvändning. SHALLOT minskar risken med air-gapped nyckeldistribution, men har ännu ingen automatisk nyckelrotation vid omstart. Ett framtida alternativ är att lagra sekvensnumret i flash eller EEPROM.

## Konstant-tidsjämförelse

HMAC-verifiering använder XOR-ackumulering i stället för `memcmp`. Jämförelsen går igenom hela HMAC-värdet oavsett var en avvikelse finns, vilket motverkar timing-attacker där en angripare försöker härleda korrekta byte från svarstider.

## AES-CCM som framtida alternativ

AES-CCM kombinerar kryptering och autentisering i en AEAD-mod och skulle minska behovet av separat HMAC. RP2350 kan använda AES-CCM via pico-hsm och wolfSSL. CCM är lämpligt för resursbegränsade enheter eftersom det bygger på AES-blockchiffret utan Galois-fältmultiplikation.

AES-CCM ingår inte i MVP för att inte riskera tidslinjen. Det rekommenderas som en post-MVP-förbättring.

Referenser: [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final), [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), [kivicore.com](http://kivicore.com) och pico-hsm på GitHub.

## Hårdvarurot för PAW-nycklar (PRO-54 tillägg)

### Produktionskrav
PAW-nycklar (operationsnyckel, `kMac`/`kEnc`, Ed25519-identiteter om de
införs) ska i produktion bo i secure element eller motsvarande
hårdvarurot med minst: (a) nyckelgenerering/lagring som aldrig exponerar
rått material utanför elementet, (b) säker uppstart (verified/secure
boot) som vägrar manipulerad firmware, (c) krypterad eller åtkomstskyddad
flash så att avdumpning inte ger nycklar eller klonbar image, (d) fysisk
manipulationsresistens anpassad till hotbilden (passivt skydd räcker för
prototypmiljö; aktivt skydd vid fientlig fysisk åtkomst).

### Prototypens begränsningar
Feather RP2350 / Pico 2 (RP2350) saknar secure boot, flashkryptering och
secure element: UF2 kan flashas via BOOTSEL av var och en med fysisk
åtkomst, flash kan dumpas, SRAM har ingen ECC och e-paper är bistabil.
Nycklarna skyddas därför endast av SRAM-volatilitet (dör med strömmen),
fail-closed logik och fysisk procedursäkerhet — giltigt för bänk, inte
för produktion.

### Hot som kvarstår utan secure boot/flashkryptering
- Omflashning till angriparfirmware via BOOTSEL (fullständig
  kompromettering vid fysisk possession).
- Flash-dump: ger ingen nyckel (SRAM-only) men avslöjar protokollogik
  och möjliggör kloning av beteende samt offline-analys.
- Kallstarts-SRAM-kvarlevor och bitfel (ingen ECC) — K7.
- Fryst e-paper-bild vid strömavbrott (vilseledande indikation, ingen
  åtkomst).
- FIDO2 admin-token kan dumpas (se PRO-55 risk 2/10).

### Realistiska post-MVP-alternativ
1. Externt secure element över I2C (t.ex. ATECC608-klass) för
   nyckellagring + P-256/Ed25519 i elementet; RP2350 håller endast
   sessionsflyktiga värden.
2. MCU med hårdvarurot (t.ex. STM32U5 TrustZone + secure boot + OTP,
   redan delvis tillgänglig på UNO-Q-sidan) för DEN/PAW-nästa generation.
3. Krypterad provisionering med HSM-hållen KEK + nyckelrotation och
   återkallelse via signerad blocklist (blocklist-flödet finns, privat-
   nyckelns HSM-process saknas — PRO-55 risk 3).
4. Först: oberoende kryptoaudit + sidokanalsmätning innan hårdvarulåsning
   (låser annars in ogranskade primitiver).
