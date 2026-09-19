# 04 — CLI-registry för argparse + TUI

**What to build:** ett kommando-registry (namn/hjälp/args/run/TUI-post)
som driver både argparse och TUI-dispatch; befintliga kommandon
migreras inkrementellt, inkl. demo/explain in i TUI.

**Blocked by:** None — can start immediately.

**Status:** done

- [x] Registry äger registrering; cli.py + tui.py konsumerar
- [x] Minst två kommandon migrerade som bevis (ett med TUI-flöde)
- [x] test_cli + test_tui gröna utan duplicerad wiring
