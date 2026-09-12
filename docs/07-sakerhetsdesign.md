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
