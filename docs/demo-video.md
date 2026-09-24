# Demo-video: NEKAD + ÅTKOMST (MVP, TEST-ONLY bänk)

Alla kommandon är copy-paste-säkra i zsh/bash — ingen shell-variabel behövs.
Flaggorna: `BatchMode` hindrar lösenordsfrågor som hänger tagningen,
`HostKeyAlias` återanvänder den verifierade värdnyckeln.

## Pre-flight (5 min före tagning)

```sh
# 1. Båda portarna ska finnas:
ssh -o BatchMode=yes -o HostKeyAlias=mamabear.tailnet.example mamabear-cli \
  'ls /dev/ttyACM*'
# 2. Snabb avläsning (code 0 = allt intakt):
ssh -o BatchMode=yes -o HostKeyAlias=mamabear.tailnet.example mamabear-cli \
  'timeout 8 shallot monitor --device den --port /dev/ttyACM0'
```

Ser du `AUTHENTICATED (code 0)`: kör. Annars: se Återställning.

## Tagning (ett kommando)

```sh
ssh -o BatchMode=yes -o HostKeyAlias=mamabear.tailnet.example mamabear-cli \
  'python3 -' < tools/bench/record-demo.py | \
  tee "demo-recording-$(date -u +%Y%m%dT%H%M%SZ).txt"
```

Skriptet provisionerar allt från scratch (tål torkade nycklar), kör
Act 1 (fel nyckel → DENIED) och Act 2 (rätt nyckel → GRANTED), skriver
verdict per akt. Filma terminal + e-paper samtidigt. Avslutar det med
`act1=OK act2=OK` är tagningen godkänd.

## Två separata tagningar (en akt per video)

```sh
ssh -o BatchMode=yes -o HostKeyAlias=mamabear.tailnet.example mamabear-cli \
  'python3 - act1' < tools/bench/record-demo.py | \
  tee "demo-act1-$(date -u +%Y%m%dT%H%M%SZ).txt"

ssh -o BatchMode=yes -o HostKeyAlias=mamabear.tailnet.example mamabear-cli \
  'python3 - act2' < tools/bench/record-demo.py | \
  tee "demo-act2-$(date -u +%Y%m%dT%H%M%SZ).txt"
```

`act1` kör endast Act 1 (fel nyckel → DENIED) och avslutas med ASCII-verdict
FAILED; `act2` kör endast Act 2 (rätt nyckel → GRANTED) och avslutas med
ASCII-verdict AUTHENTICATED. Godkänd slutrad per tagning: `act1=OK`
respektive `act2=OK`. Verdict-bannern visas bara när resultatet matchar
förväntningen — en avvikelse rapporteras som DEVIATION utan banner.

## Återställning (om något är torkat/nere)

Samma kommando som tagning — det återställer baslinjen först. Räcker
inte det: `BG STATUS`-tystnad eller saknade portar betyder omstart av
värd/kort behövs; börja om från Pre-flight.

## Scope-raden (säg högt i videon)

“TEST-ONLY-bänk: testnycklar, test-signerad blocklista, UART-dock.
LoRa är ur scope. E-paper är indikation, inte behörighet.”
