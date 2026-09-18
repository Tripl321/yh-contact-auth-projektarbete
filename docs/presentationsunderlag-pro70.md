# SHALLOT — presentationsunderlag (PRO-70, icke-tekniskt)

**Status:** Utkast 2026-09-18 | Målgrupp utan teknikbakgrund. Sakligt:
beskriver vad som är byggt och testat i kod, vad som kräver fysisk bänk
och vad som återstår. Inga produktions- eller compliancelöften.

## 1. Problemet

Vem får öppna eller styra något viktigt — en dörr, ett skåp, en maskin?
Nycklar kan kopieras, koder kan avlyssnas och ett nekat försök märks inte
alltid. SHALLOT svarar på frågan: hur vet dörren med säkerhet att rätt
bricka är på plats, just nu — och hur blir varje nekat försök synligt?

## 2. Lösningen i en mening

En ID-bricka och en docka som känner igen varandra genom ett kort,
krypterat handslag varje gång — misslyckas något, förblir dörren låst
och händelsen loggas.

## 3. Hur den lokala autentiseringen fungerar (begripligt)

1. Brickan dockas. Dockan skickar en engångsfråga (slumpad vid varje
   tillfälle — kan aldrig återanvändas).
2. Brickan räknar fram svaret med sin hemliga nyckel och skickar tillbaka.
3. Dockan kontrollerar svaret. Stämmer det — öppet en kort stund. Stämmer
   det inte, är för sent eller uteblir — fortsatt låst, alltid.
4. Nyckeln finns bara i brickans och dockans arbetsminne och raderas vid
   fel eller omstart. Brickans display visar förloppet och slocknar
   tillbaka till låst läge av sig själv.

Poängen: det finns inget att avlyssna och återanvända — varje handslag
är unikt, och tystnad eller fusk betyder alltid nej.

## 4. Demo (3 minuter, hårdvarufri)

```bash
shallot simulate auth --scenario success    # beviljad: visar hela kedjan
shallot simulate auth --scenario wrong-key  # nekad: fail-closed i praktiken
shallot demo incident                       # simulerat driftlarm + avslöjande
```

Berätta under tiden: första kommandot visar hur det ser ut när allt
stämmer; andra visar att fel nyckel ger ett tydligt, loggat nej; tredje
visar hur ett övervakningssystem skulle se larmet (märkt simulering).

## 5. Säkerhetsnytta (belagd, inte lovat)

- Nekande är normalläget: fel, timeout och omstart låser — bevisat i
  automatiska tester (500+), inte bara påstått.
- Nycklar lämnar aldrig enheterna utom som okänsliga fingeravtryck och
  raderas efter bruk.
- Serviceåtkomst (break-glass) kräver två personer, är tidsbegränsad till
  minuter, larmar och loggar varje användning.
- Administratörsgodkännande sker med fysisk säkerhetsnyckel (FIDO2).

## 6. Begränsningar (säg högt)

- Prototyp på labbkort: ingen har ännu bevisat tiderna på fysisk
  hårdvara i alla lägen — bänkverifiering pågår.
- Den som fysiskt håller enheten kan flasha om den — stöldskyddet är
  idag proceduriellt, inte kryptografiskt.
- Larmloggarna är flyktiga och måste fångas av övervakande personal.
- Detta är ingen certifierad produkt och ersätter inte nödstopp eller
  annan fysisk processäkerhet.

## 7. Nästa steg

1. Fysisk bänk: bevisa tider, felvägar och nyckelhantering på riktig
   hårdvara (pågående testplan PRO-63).
2. Oberoende granskning av kryptodelarna.
3. Hårdvarurot (secure element) för nycklarna före varje pilot.
4. Pilot i avgränsad miljö — aldrig som enda säkerhetslager dag ett.
