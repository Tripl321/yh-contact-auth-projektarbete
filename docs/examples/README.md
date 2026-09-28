# Anonymiserade exempelfiler

Filer i den här katalogen är **schema-exempel, inte driftdata**. De är
genererade för att beskriva filformaten och innehåller ingen riktig
credential, ingen riktig publ nyckel, inga användarnamn, inga interna
värdnamn och ingen tidsstämplad driftinformation.

| Fil | Beskriver | Produceras av |
| --- | --- | --- |
| `admin-01.approval.example.json` | Godkännande-dokument för en FIDO2-credential | `shallot fido2 credential export` |
| `mamabear-status.example.json` | Tidsstämplat resultat av fjärrstatus/självtest | `shallot mamabear status` |

Namnen slutar på `.example.json` just för att de inte ska förväxlas med
verkliga utdata — och för att `.gitignore`-reglerna `*.approval.json` och
`mamabear-status-*.json` inte ska fånga dem.

## Varför verkliga filer inte versionstyrs

- **Approval-filer** innehåller `credential_id` och publik COSE-nyckel för en
  verklig autentisator, plus `rp_id`/`origin`/`registered`. Det är
  autentiserings- och driftmetadata som hör hemma i lokal Credential Store
  (`~/.shallot/`) och i den godkända katalogen på noden — inte i git.
- **Status-filer** innehåller `host_alias` (SSH-alias som pekar ut en nod),
  tidsstämpel och sanerad fjärr-output. Det är driftdata.

Se `.gitignore` och notisen i `README.md`.

## Sanering

Exemplen är sanerade manuellt. Vid egen export ska du hellre använda en
tillfällig katalog utanför repot:

```sh
shallot fido2 credential export --credential <id> --output "$HOME/.shallot/op-01.approval.json"
```
