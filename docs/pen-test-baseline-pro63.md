# Pen-testunderlag mot baseline (PRO-63)

**Status:** Utkast 2026-09-18 | PRO-63 | Planerade fall mot aktuell
implementation (`pro-demo-incident-cli`). Varje fall anger förväntat
fail-closed-resultat och vilken fysisk bänkevidens som krävs. **Inget
fall är utfört — inga hårdvarupåståenden görs här.** Resultat loggas per
fall vid körning (USB-loggutdrag + observatör + datum).

Regler: endast bänkenheter avsatta för test; produktionsexemplar rörs
aldrig; varje fall avslutas med omstart till verifierat låst läge.

## PT-01 Replay av giltigt RESPONSE

- **Utförande:** fånga giltigt RESPONSE på dock-UART (logikanalysator),
  återinjicera i nästa session efter omstartad challenge.
- **Förväntat:** DENIED (HMAC_MISMATCH — svaret binder till gammal nonce;
  dessutom nollad nonce efter fel). ACK 0x00.
- **Evidens:** USB-logg `FAILED:hmac mismatch (code 5)` + ACK-byte på tråd.

## PT-02 Felaktig nyckel (PAW med avvikande master)

- **Utförande:** provisionera PAW med annan nyckel än DEN, kör session.
- **Förväntat:** DENIED (HMAC_MISMATCH), ACK 0x00; PAW visar FAILED efter
  ACK-timeout. Ingen accessindikering kvarstår efter 30 s-fönstret.
- **Evidens:** båda sidors USB-loggar + e-paper-foto efter 60 s (låst läge).

## PT-03 Timeout / trunkerad RESPONSE

- **Utförande:** skicka ofullständig RESPONSE (5 av N byte) inom 2 s;
  separat fall: fullständig men försenad (>2 s).
- **Förväntat:** DENIED (TIMEOUT, kod 1); sen giltig RESPONSE nekas likaså
  (deadline passerad). `test_pro87`-mirrors definierar ramgränserna.
- **Evidens:** `FAILED:timeout (code 1)`, tidsstämplad tråddump.

## PT-04 Paketförlust och korruption

- **Utförande:** bitfel i nonce/HMAC/CRC (ett i taget), fel ramtyp mot
  CHALLENGE_SENT, överstor payload, resynk-brus före SYNC.
- **Förväntat:** DENIED med respektive kod (2/3/4/5); skanner återhämtar
  SYNC; ingen krasch, ingen hängning (loop svarar <100 ms).
- **Evidens:** kod per injiceringstyp + svarstidsobservation.

## PT-05 Fysisk possession (stulen PAW / stulen DEN)

- **Utförande:** (a) läs av flash via UF2/USB-masslagring; (b) försök
  autentisera stulen PAW mot DEN efter att PAW nollställts/nyckel rensats;
  (c) flasha modifierad firmware via BOOTSEL.
- **Förväntat:** (a) ingen nyckel i dump (SRAM-only) — verifiera med
  strängsökning i imagen; (b) DENIED; (c) enheten exekverar angripar­kod —
  **förväntat lyckat angrepp** (ingen secure boot): dokumentera som
  bekräftad designbegränsning, inte som förvåning.
- **Evidens:** dump-hash + söklogg, DEN-logg, foto av angriparbeteende.

## PT-06 Break-glass-missbruk

- **Utförande:** (a) `BG CONFIRM` utan ARM; (b) fel ticket; (c) ticket
  återanvänd efter förfall; (d) okänt kommando i beviljat läge;
  (e) bekräfta efter ARM-fönster; (f) operatörsroll: en person utför
  båda stegen.
- **Förväntat:** (a–e) DENIED + audit + låst läge; beviljat läge förfaller
  efter 120 s; (f) tekniskt möjligt — förväntat lyckat, ska synas som
  två auditposter utan rollskillnad (bekräftar dokumenterad restrisk).
- **Evidens:** `[AUDIT]`-sekvenser per delfall + LED/lapp-observation.

## PT-07 Provisioneringsstörning

- **Utförande:** avbryt PRO-46 mitt i (koppla USB), skicka fel CRC,
  fel längd, nollnyckel; starta ny handshake mitt i session.
- **Förväntat:** PROV_FAILED, buffertar torkade, lagrad nyckel borta vid
  timeout; ny handshake nollställer. DEN stannar i DENIED.
- **Evidens:** `PROV_FAILED`-logg + efterföljande nekad challenge.

## Evidenskrav (alla fall)

1. Tidsstämplade USB-loggar sparade som filer (inte klippta citat).
2. Tråddump där ramen är relevant (salting av förväntan förbjuden —
   dumpen ska kunna motbevisa).
3. Avslutande omstart med verifierat låst läge i logg.
4. Observatör och datum per fall. Fall utan detta räknas som ej utfört.
