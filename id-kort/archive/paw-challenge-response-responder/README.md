# ARKIVERAD — Fristående LoRa/Paw-respondern (RadioLib/LoRa)

**Denna katalog är arkiverad. Aktivera den INTE — RadioLib/LoRa är enligt #14 explicit ur aktivt scope.**

## Varför är den här?

Den fristående respondern `paw-challenge-response.ino` verkar ha **plockats upp igen**
av misstag (den hamnade i aktiv id-kort-scope trots att beslutet #14 var att arkivera den).
Den arkiveras här med denna banner så att inget framtida arbete råkar aktivera den.

## Beslut

- Referens: **#14** "arkivera RadioLib/LoRa-respondern ur aktivt scope"
- Active scope: `docs/00-scope.md` — LoRa är explicit ur scope för denna nod.
- Den enda firmware som ska byggas/aktiveras är `id-kort/paw-main/paw-main.ino`
  (oförändrad, 0 diff mot origin-tipen).

## Förbjudet

- **Ingen** `#include <RadioLib.h>` i aktiv firmware.
- **Ingen** LoRa-P2P-sändning på 868 MHz utan ny duty-cycle-verifiering per AGENTS.md.

## Säkerhetsnot (historik)

Den arkiverade `.ino`-filen innehåller en hårdkodad utvecklingsnyckel
(`MASTER_KEY = 00..0F`, publik testvektor). Den är historik och byggs inte
längre av CI (jobbet `build-paw-pro52` är borttaget). Återaktivera aldrig
filen utan att ersätta nyckeln med provisionering eller explicit
opt-in-guard enligt mönstret i `plc/edge-challenge-response/`.
