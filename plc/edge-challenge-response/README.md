# Edge challenge-response (PLC, LoRa P2P)

Bänknod för PRO-52/PRO-81 challenge-response över LoRa P2P (868,1 MHz).
 scope: LoRa är explicit ur aktivt MVP-scope (`docs/00-scope.md`) — denna
nod är ett bänkverktyg, ingen produktionsfirmware.

## Utvecklingsnyckel (TEST-ONLY)

Sketchen bäddar in den publika bänkvektorn `MASTER_KEY = 00..0F` så att
bänkparet kan köras utan provisioneringsflöde. Skydd:

- Kompilering kräver explicit `-DEDGE_ALLOW_DEV_KEY=1`, annars `#error`.
- CI-bänkjobbet (`build-edge-pro52`) passerar flaggan explicit.
- `shallot doctor` flaggar filen om opt-in-guardet saknas.
- Nyckelmaterial loggas aldrig — endast statuskoder på Serial.

Bygg aldrig en artefakt från denna fil för annat än bänken.
