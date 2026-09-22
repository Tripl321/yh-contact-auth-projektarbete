# 19 — FIDO2-härdningsspår (proof of concept)

**Status:** Utkast | **Scope:** design + CLI-PoC med fysisk authenticator
som standardläge (CTAP2 mot Pico Fido/Pico Key) samt explicit
mock-läge (`--mock`, SIMULATED / TEST-ONLY).
Kompletterar — ersätter inte — UART/HMAC-autentiseringen mellan PAW
och DEN. FIDO2 skyddar användar- och adminidentitet; UART/HMAC skyddar
PAW–DEN-kommunikationen. Detta är **inte en certifierad
FIDO2-implementation**.

## 1. Syfte och avgränsning

- Inför användaridentitet + användarnärvaro för känsliga administrativa
  åtgärder (registrera/spärra credentials, framtida adminfunktioner).
- Automatisera registrering, assertion-verifiering,
  credential-livscykel, negativa tester och auditunderlag.
- Hålls isolerat från UART-MVP:n: egen CLI-grupp (`shallot fido2`),
  egen lagring, egen testsvit. UART-sviterna påverkas inte.
- CLI:t använder fysisk authenticator som standard (kräver beröring,
  ingen flagga); mockat läge kräver explicit `--mock` och märks
  SIMULATED / TEST-ONLY. Saknad enhet/beroende/USB-åtkomst nekar med
  nästa steg — aldrig tyst fallback till mock. CLI:t ger aldrig DEN/PAW
  skrivkommandon (endast ALLOW/DENY-text).

## 2. Trust boundaries

```
┌─────────────┐  auktoritativ källa   ┌──────────────────┐
│  MamaBear   │  för godkända         │  Admin/operatör  │
│ Trust Root  │  credentials+policy ─▶│  (användar-ID +  │
└─────────────┘                       │  användarnärvaro)│
                                      └────────┬─────────┘
                                               │ FIDO2-assertion
                                               ▼ (ALLOW/DENY, läsande)
                                      ┌──────────────────┐
                                      │  Administrativa  │
                                      │  funktioner      │
                                      └──────────────────┘

┌──────────┐  UART/HMAC (oförändrat)  ┌──────────┐
│   PAW    │ ◀───────────────────────▶│   DEN    │  lokala fail-closed beslut
└──────────┘  challenge-response      └──────────┘
```

- **Betrodda:** MamaBear som policykälla; lokal CLI-lagring för
  credential-metadata (integritet via filrättigheter, ingen sekretess
  krävs — inga hemligheter lagras).
- **Obetrodda:** nätverk/terminal (replay, MITM) — hanteras med
  singelbruk-challenges, timeout (120 s), origin/RP-ID-bindning och
  konstanttidsjämförelse av mock-signaturer.
- **Utanför spåret:** PAW–DEN-länken (ägs av UART-MVP:n), säker
  förvaring av framtida produktionsnycklar, certifierad
  authenticator-hårdvara.

## 3. Credential-livscykel

```
register (bekräftelse) → active ──authenticate──▶ ALLOW/DENY + audit
   │                         │ revoke (bekräftelse)
   │                         ▼
   │                      revoked ──authenticate──▶ DENY (revoked-credential)
   └── set-policy (bekräftelse) → ändrar UV-policy, auditas som set-policy
```

- Lagrat per credential: ID, användar-ID, skapad-tid, status, policy
  (`user_presence`, `rp_id`, `origin`, backend, läge). Aldrig privata
  nycklar — lagringen avvisar förbjudna fält.
- Användar-ID:n är anonyma token (`admin-01`); e-post avvisas som ID
  och maskeras i output.
- Testdata (`~/.local/share/shallot/fido2-test/`) separeras från
  framtida produktionsdata via `SHALLOT_FIDO2_STORE`.

## 4. Ceremonier och fail-closed-regler

Registrering: challenge (32 byte) → mock-attestation verifieras mot
challenge/origin/RP-ID/närvaro → metadata sparas + auditpost.
Assertion: känd credential → aktiv status → färsk oanvänd challenge →
origin → RP-ID → närvaro → signatur. Första felet vinner; allt annat
är DENY (`unknown-credential`, `revoked-credential`, `replay`,
`timeout`, `wrong-origin`, `wrong-rp-id`, `no-user-presence`,
`invalid-signature`).

## 5. Auditflöde

Append-only JSONL (`audit.jsonl` bredvid lagringen), en post per
`register`/`revoke`/`authenticate` (inkl. DENY med skäl). Poster
innehåller endast sanerade fält (trunkerade credential-ID:n).
Korrupta rader hoppas över vid läsning — visning kraschar aldrig.
UV-policy (`preferred`/`required`) lagras per credential; `required`
kan sättas vid registrering (`--require-uv`) eller tvingas per beslut,
och verkställs mot enhetens UV-flagg (fail closed utan den).

## 6. Kända restrisker

| Risk | Läge |
|---|---|
| Mock-backend (HMAC) är ingen säkerhetsmekanism; PoC övar endast ceremonier | Fysisk authenticator är standardläge; mock kräver explicit `--mock` (SIMULATED / TEST-ONLY) |
| HW: self-attestation accepteras (ingen vendor-CA); `none` accepteras | Explicit policy, dokumenterad; x5c/BASIC och övriga format avvisas (inga trust anchors) |
| HW: enhet utan sign-counter ger ingen klondetektion | Accepterat, loggas implicit (counter 0/0); regression vid counter>0 = DENY |
| HW: stulen admin-token kan flash-dumpas utan Secure Boot | Rekommendation: Secure Boot + OTP på ESP32-S3; RP2040 saknar skyddet |
| Pico Fido är AGPL-3.0 | Stock-firmware internt bruk OK; inga modifierade byggen distribueras utan licensprövning |
| Ingen HW-nyckelförvaring; mock-nycklar deriveras i mjukvara | Accepterat i PoC (inga riktiga hemligheter hanteras) |
| Lokal JSON-lagring utan åtkomstkontroll utöver filrättigheter | Accepterat i PoC (inga hemligheter lagras; HW lagrar endast publik nyckel + counter) |
| RP-ID/origin är PoC-värden (`shallot.local`) | Måste bindas till verklig RP vid produktionssättning |
| FIDO2-beslut verkställs ännu inte mot adminfunktioner (endast text) | Framtida arbete; idag ingen koppling till DEN/PAW |

## 7b. Standardläge + installationskrav (2026-09-22)

- **Standardläge är fysisk authenticator** (CTAP2/HID, kräver beröring,
  ingen flagga). Mockat läge kräver explicit `--mock` och märks alltid
  `SIMULATED / TEST-ONLY` (banner + audit `backend: mock`).
- **Inget tyst fallback:** saknad enhet, saknat `fido2`-paket eller
  saknad USB-åtkomst nekar med nästa steg i felmeddelandet.
- **Lagring:** beständig produktionslagring under
  `~/.local/share/shallot/fido2` — fungerar utan miljövariabler
  (`SHALLOT_FIDO2_STORE` endast för tester/edge).
- **Installationskrav:** `pip install fido2 pyserial` (se pyproject),
  USB-åtkomst till enheten (Linux: udev-regel eller root för HID;
  verifiera med `shallot fido2 device list`), samt en CTAP2-capable
  authenticator (verifierad: Pico Key, CTAP 2).
- **Demoflöde:** `shallot fido2 simulate --scenario <namn>` (register →
  authenticate → ALLOW/DENY mot minneslagring, alltid TEST-ONLY).

## 8. Bänkverifiering (2026-09-14, Pico Fido @ ESP32-S3 Nano)
- Enhet syns som `Pico Key` över USB HID, CTAP 2. `device list` bekräftar.
- Registrering OK: `packed` self-attestation accepterad enligt policy.
- 2× assertion ger ALLOW med sign_count 7 → 9 (monoton, steg >1 —
  förenligt med global räknare; `>`-jämförelsen hanterar det).
- Bänkfynd 1: UV `preferred` triggar PIN-prompt mot PIN-kapabel enhet
  även utan satt PIN — CLI:t förklarar läget och avbryter rent på tom rad.
- Bänkfynd 2: PicoKey App är betalvägg (29,49 €/enhet); PIN/reset hanteras
  gratis via webbläsarens säkerhetsnyckel-sida. Glömd PIN = fabriksreset
  (ingen väg runt per CTAP2-design).
- Secure Boot + OTP ej aktiverat på bänkenheten — rekommendation kvarstår.

## 7. Relation till UART/HMAC

| Aspekt | UART/HMAC (MVP) | FIDO2-spåret (PoC) |
|---|---|---|
| Skyddar | PAW–DEN-kommunikation (brickans äkthet) | Användar-/adminidentitet + närvaro |
| Beslutsfattare | DEN, lokalt fail-closed | RP-verifiering, ALLOW/DENY-text |
| Hemlighet | Delad nyckel i SRAM | Inga lagrade hemligheter (mock) |
| Transport | Dockad UART (Serial1) | Lokal CLI-ceremoni |
| Status | Aktiv MVP | Isolerad PoC, ej verkställande |

## 9. MamaBear-godkännande (manuell procedur v1)

MamaBear är Trust Root och ska vara auktoritativ källa för godkända
admin-credentials — men CLI:ts `mamabear`-läge är läsande av design och
MPU-skriptet har inget credential-begrepp. Därför finns ännu ingen
automatisk överföring; godkännande sker manuellt:

1. `shallot fido2 credential export --credential <id> --output <user>.approval.json`
   (endast publik metadata; se README för exakt procedur inkl.
   fingeravtrycksverifiering över andra kanalen).
2. Kopiera filen till MamaBear över befintlig Tailscale-SSH till
   `/home/user/shallot/admin-credentials/approved/`.
3. Auditpost i separat logg på MamaBear
   (`/home/user/shallot/audit/admin_approvals.jsonl`) — aldrig i
   provisioneringsloggen, för att inte blanda Domäner.

Detta är bokföring, ej verkställighet: inget konsulterar MamaBears
godkännanden vid autentisering ännu.

Nästa steg (beslutspunkt, ej implementerat): `mamabear approve` där
MamaBear countersignerar godkännandet med sin Ed25519-nyckel — samma
mönster som blocklist-signeringen (docs/17). Det kräver ny kod på
båda sidor (MPU-append + CLI-ceremoni) och förblir manuellt bekräftat.
