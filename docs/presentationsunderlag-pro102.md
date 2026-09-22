# SHALLOT — bildmanus 8 minuter (PRO-102, icke-tekniskt)

**Status:** Utkast 2026-09-22 | Målgrupp utan teknikbakgrund. Max 8 slides,
ca 1 minut per slide. Sakligt: beskriver vad som är byggt och testat i kod,
vad som kräver fysisk bänk och vad som återstår. Inga produktions- eller
compliancelöften. LoRa P2P som autentiseringstransport är arkiverad
(`docs/archive/`) och beskrivs här endast som avgränsning — aldrig som
aktiv funktionalitet.

## Slide-disposition (8 min)

1. Problem och målbild (1:00)
2. Medveten avgränsning: LoRa → aktiv UART-dockning (1:00)
3. Systemöversikt: MamaBear, DEN och PAW (1:00)
4. Challenge-response-flödet (1:00)
5. Fail-closed: godkänn eller neka (1:00)
6. Resultat: tester och säkerhetskontroller (1:00)
7. Begränsningar och återstående fysisk verifiering (1:00)
8. Slutsats och nästa steg (1:00)

---

## 1. Problem och målbild

**Bild:** En dörr med två scenarier sida vid sida — till vänster en kopierad
nyckel som glider in obemärkt, till höger en bricka som dockas och får ett
tydligt ja eller nej med loggrad händelse.

**Sägs (ca 1 min):** Vem får öppna eller styra något viktigt — en dörr, ett
skåp, en maskin? Nycklar kan kopieras, koder kan avlyssnas, och ett nekat
försök märks inte alltid. Målbilden: dörren vet med säkerhet att rätt bricka
är på plats just nu — och varje nekat försök blir synligt i efterhand.

## 2. Medveten avgränsning: LoRa → aktiv UART-dockning

**Bild:** En radiovåg som tonas ut till grått med etiketten "arkiverad", och
en pil över till en bricka som sätts fysiskt i en docka — etikett "aktiv".

**Sägs (ca 1 min):** Från början prövade vi radio (LoRa) som bärare av
handskaket. Vi lade det spåret åt sidan medvetet: radio går att avlyssna och
störa på avstånd, och reglerna för frekvensbandet begränsar hur ofta man får
sända. Kvar finns den starkaste varianten: brickan dockas fysiskt, och hela
handsaket går över sladd i dockan. Radiokoden finns kvar i arkivet som
referens — den är inte aktiv funktionalitet.

## 3. Systemöversikt: MamaBear, DEN och PAW

**Bild:** Tre boxar i kedja — MamaBear (nyckelsmed) → pil "delar ut nyckel via
USB" → DEN (docka/lås) och PAW (bricka). Under DEN+PAW: "handslag i dockan".

**Sägs (ca 1 min):** Tre roller, inget mer. MamaBear är nyckelsmeden som skapar
och delar ut hemliga nycklar via USB. PAW är brickan du håller i handen. DEN
är dockan vid dörren som fattar beslutet. Nycklarna bor bara i enheternas
arbetsminne och försvinner vid fel eller omstart — det finns ingen
nyckeldatabas att stjäla.

## 4. Challenge-response-flödet

**Bild:** Tre numrerade steg mellan docka och bricka: 1) dockan skickar en
engångsfråga, 2) brickan räknar fram svaret med sin nyckel, 3) dockan
kontrollerar och öppnar en kort stund. En klocka markerar "max 2 sekunder".

**Sägs (ca 1 min):** Varje gång brickan dockas händer tre saker på under två
sekunder: dockan ställer en engångsfråga som aldrig går att återanvända,
brickan räknar fram svaret med sin hemliga nyckel, och dockan kontrollerar
svaret. Stämmer det öppnas det — en kort stund. Det finns inget att avlyssna
och spela upp igen, eftersom frågan är ny varje gång.

## 5. Fail-closed: godkänn eller neka

**Bild:** Ett flödesschema med en väg till grön bock ("allt stämmer") och alla
andra vägar — fel svar, för sent svar, inget svar, omstart — till samma röda
låssymbol ("fortsatt låst").

**Sägs (ca 1 min):** Systemets grundregel är enkel: minsta avvikelse betyder
nej. Fel svar, för sent svar, uteblivet svar eller omstart — allt slutar i
fortsatt låst och loggad händelse. Det finns exakt en väg till ja, och den
kräver att allt stämmer. Brickans display visar förloppet och faller alltid
tillbaka till låst läge av sig själv.

## 6. Resultat: tester och säkerhetskontroller

**Bild:** En mätare med "566 automatiska tester — alla gröna" samt fyra
bockar: nekande är normalläge, nycklar raderas efter bruk, serviceåtkomst
kräver två personer och loggas, admin godkänns med fysisk säkerhetsnyckel.

**Sägs (ca 1 min):** 566 automatiska tester, verifierade 2026-09-22 — alla
gröna. De bevisar det som går att bevisa utan hårdvara: att nekande är
normalläget, att nycklar aldrig lämnar enheterna utom som okänsliga
fingeravtryck, att serviceåtkomst kräver två personer och loggar varje
användning, och att administratörer godkänns med fysisk säkerhetsnyckel.

## 7. Begränsningar och återstående fysisk verifiering

**Bild:** En bänk med labbkort och en checklista där kodraderna är ibockade
men hårdvaruraderna står som "kvar": tider på riktig hårdvara, nyckelhantering
i arbetsminne, stöldskydd.

**Sägs (ca 1 min):** Ärlighetsdelen — säg högt: detta är en prototyp på
labbkort. Koden är testad, men tider, felvägar och nyckelhantering måste ännu
bevisas på fysisk hårdvara i alla lägen — den bänkverifieringen pågår. Den som
fysiskt håller enheten kan flasha om den, så stöldskyddet är idag
proceduriellt, inte kryptografiskt. Detta är ingen certifierad produkt.

## 8. Slutsats och nästa steg

**Bild:** En trappa med tre steg: 1) fysisk bänk, 2) oberoende granskning +
hårdvarurot för nycklarna, 3) pilot i avgränsad miljö — aldrig som enda
säkerhetslager dag ett.

**Sägs (ca 1 min):** Slutsats: handskaket fungerar i kod, nekar som det ska,
och avgränsningen till dockning ger den starkaste säkerhetspositionen. Nästa
steg i ordning: bevisa allt på fysisk bänk, låt oberoende ögon granska
kryptodelarna, lägg nycklarna i hårdvarurot före varje pilot — och börja
pilot i avgränsad miljö, aldrig som enda säkerhetslager dag ett. Tack —
frågor?
