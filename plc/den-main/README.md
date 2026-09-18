# DEN docked UART auth (PRO-53)

DEN-side session master for the PAW↔DEN docked UART link (`docs/11-dockat-uart-protokoll.md`). Pico 2 (RP2350).

- **Transport: UART (Serial1 @115200, TX=GPIO0, RX=GPIO1)** — the current and only in-scope transport. LoRa is explicitly out of scope.
- **State machine: `DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED`** — fail-closed across the full session lifecycle.
- Flow per session: `CHALLENGE(8B TRNG nonce)` → wait ≤2000 ms → `RESPONSE(32B HMAC)` → constant-time verify → `ACK(0x01/0x00)`.
- USB serial reason codes are non-secret integers 0–11; codes 9–11 belong to break-glass.

## Break-glass service mode (PRO-97)

Kortlivat, lokalt serviceläge för definierade åtgärder vid övervakad återställning — inte generell upplåsning av det underliggande systemet och aldrig en ersättning för nödstopp eller annan fysisk processäkerhet. Ingen flash, inga persistenta flaggor och ordinarie auth-väg är orörd.

Definierade åtgärder i beviljat läge är `BG STATUS` (skrivskyddad flaggavläsning och audit-dump) och `BG ABORT` (återlåsning). Allt annat nekas och loggas utan verkan.

Ceremoni:
1. `BG ARM` från vilande DENIED genererar en färsk 4-byte ticket och beväpnar i 60 sekunder.
2. `BG CONFIRM <8 hex>` inom fönstret ger serviceläge i 120 sekunder med larm.
3. `BG ABORT`, timeout, felaktig inmatning eller omstart återlåser till DENIED.

Tvåpersonsmodellen är en fysisk, operativ procedur för prototypen: operatör A beväpnar och läser ticketen, och operatör B bekräftar efter fysisk överlämning. Firmwaren kräver en färsk ticket men kan inte skilja två personer åt eller bevisa en överlämning; en ensam operatör vid samma konsol kan genomföra båda stegen.

Varje användning visas med larmbanner och LED-blink samt loggas som `[AUDIT]` med sekvensnummer, tid och händelse. Auditringen är flyktig SRAM och konsolen måste fånga den.

## Build

```bash
arduino-cli lib install "Crypto@0.4.0"
arduino-cli compile --fqbn rp2040:rp2040:rpipico2 --libraries libraries --output-dir build plc/den-main/den-main.ino
```

## Bench checks

- Negative loopback: egen CHALLENGE återkommer och nekas.
- Silence: timeout leder till fail-closed deny.
- Live session: PAW krävs för `AUTHENTICATED` och ACK 0x01.
