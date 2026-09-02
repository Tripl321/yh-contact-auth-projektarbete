#!/usr/bin/env bash
#
# SHALLOT — Sync & Flash
# Hämtar senaste .ino-filerna från GitHub-repot och (om arduino-cli finns)
# kompilerar och flashar till vald komponent.
#
# Användning:
#   ./sync-and-flash.sh           # interaktivt: välj komponent
#   ./sync-and-flash.sh paw       # PAW (Feather RP2350)
#   ./sync-and-flash.sh plc       # PLC (Pico 2)
#   ./sync-and-flash.sh unoq      # UNO Q (STM32U585)
#   ./sync-and-flash.sh sync      # bara synka repo+sketchbook, inte flasha
#   ./sync-and-flash.sh list      # lista anslutna boards med port+FQBN
#
# Krav:
#   - git (finns på macOS som standard)
#   - arduino-cli (installeras automatiskt via Homebrew om det saknas)
#
# Konfiguration (miljövariabler, kan överstyras):
#   SHALLOT_REPO_DIR   var repot ska ligga    (default: ~/projects/yh-lora-auth)
#   SHALLOT_SKETCHBOOK Arduino sketchbook     (default: ~/Documents/Arduino)
#   SHALLOT_BRANCH     branch att hämta från  (default: auto: feature branch om finns, annars main)

set -euo pipefail

# ----------------------------------------------------------------------------
# Konfiguration
# ----------------------------------------------------------------------------
REPO_URL="https://github.com/Tripl321/yh-lora-auth-projektarbete.git"
REPO_DIR="${SHALLOT_REPO_DIR:-$HOME/projects/yh-lora-auth}"
SKETCHBOOK="${SHALLOT_SKETCHBOOK:-$HOME/Documents/Arduino}"
BRANCH="${SHALLOT_BRANCH:-}"   # tom = auto

# Komponentdefinitioner: namn -> (källrelativ sökväg i repo, FQBN, core-paket)
declare -A COMP_SRC=(
  ["paw"]="id-kort/paw-main/paw-main.ino"
  ["plc"]="plc/plc-key-receiver/plc-key-receiver.ino"
  ["unoq"]="key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino"
)
declare -A COMP_FQBN=(
  ["paw"]="rp2040:rp2040:adafruit_feather_rp2350_hstx"
  ["plc"]="rp2040:rp2040:rpipico2"
  ["unoq"]="arduino:zephyr:unoq"
)
declare -A COMP_CORE=(
  ["paw"]="rp2040:rp2040"
  ["plc"]="rp2040:rp2040"
  ["unoq"]="arduino:zephyr@0.90.0"
)
# Board names for detection
declare -A COMP_NAME=(
  ["paw"]="Feather RP2350"
  ["plc"]="Raspberry Pi Pico 2"
  ["unoq"]="UNO Q"
)
# Extra filer som ska kopieras med (prj.conf för UNO Q etc.)
declare -A COMP_EXTRAS_SRC=(
  ["unoq"]="key-authority/uno-q-key-authority-mcu/prj.conf"
)

# Färger
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

# ----------------------------------------------------------------------------
# Hjälpfunktioner
# ----------------------------------------------------------------------------

ensure_git() {
  if ! command -v git >/dev/null 2>&1; then
    err "git hittades inte. Installera Xcode Command Line Tools:"
    err "  xcode-select --install"
    exit 1
  fi
}

ensure_repo() {
  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Uppdaterar befintlig klon: $REPO_DIR"
    git -C "$REPO_DIR" fetch --prune origin
  else
    log "Klonar repo till: $REPO_DIR"
    mkdir -p "$(dirname "$REPO_DIR")"
    git clone "$REPO_URL" "$REPO_DIR"
    git -C "$REPO_DIR" fetch --prune origin
  fi
}

# Välj branch: om SHALLOT_BRANCH satt, använd den. Annars föredra vår
# feature-branch om den finns på origin, annars main.
pick_branch() {
  if [[ -n "$BRANCH" ]]; then
    echo "$BRANCH"
    return
  fi
  local feature="vibe/paw-line-corruption-fix-bf5bdb"
  if git -C "$REPO_DIR" rev-parse --verify "origin/$feature" >/dev/null 2>&1; then
    echo "$feature"
  else
    echo "main"
  fi
}

checkout_branch() {
  local branch
  branch="$(pick_branch)"
  log "Byter till branch: $branch"
  git -C "$REPO_DIR" checkout "$branch" -- 2>/dev/null || \
    git -C "$REPO_DIR" checkout -B "$branch" "origin/$branch"
  git -C "$REPO_DIR" reset --hard "origin/$branch" >/dev/null
  ok "På branch $(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD) @ $(git -C "$REPO_DIR" rev-parse --short HEAD)"
}

# Kopiera en .ino (och ev. extra filer) från repo till sketchbook.
# Varje sketch måste ligga i en mapp med samma namn som .ino-filen.
sync_component() {
  local comp="$1"
  local src="${COMP_SRC[$comp]}"
  local src_full="$REPO_DIR/$src"
  if [[ ! -f "$src_full" ]]; then
    err "Källfil saknas: $src_full"
    return 1
  fi
  local sketch_name
  sketch_name="$(basename "$src" .ino)"
  local dest_dir="$SKETCHBOOK/$sketch_name"
  mkdir -p "$dest_dir"
  cp "$src_full" "$dest_dir/$sketch_name.ino"
  ok "Synkade $comp -> $dest_dir/$sketch_name.ino"

  # Extra filer (prj.conf etc.)
  if [[ -n "${COMP_EXTRAS_SRC[$comp]:-}" ]]; then
    local extra_src="$REPO_DIR/${COMP_EXTRAS_SRC[$comp]}"
    if [[ -f "$extra_src" ]]; then
      cp "$extra_src" "$dest_dir/$(basename "$extra_src")"
      ok "Synkade extra: $(basename "$extra_src") -> $dest_dir"
    fi
  fi
}

sync_all() {
  local comps=("paw" "plc" "unoq")
  for c in "${comps[@]}"; do
    sync_component "$c" || warn "Kunde inte synka $c"
  done
}

# ----------------------------------------------------------------------------
# arduino-cli-hantering
# ----------------------------------------------------------------------------

ensure_arduino_cli() {
  if command -v arduino-cli >/dev/null 2>&1; then
    return 0
  fi
  warn "arduino-cli hittades inte. Försöker installera via Homebrew..."
  if ! command -v brew >/dev/null 2>&1; then
    err "Homebrew är inte installerat. Installera från https://brew.sh"
    err "Kör sedan: brew install arduino-cli"
    return 1
  fi
  brew install arduino-cli
  if ! command -v arduino-cli >/dev/null 2>&1; then
    err "Installationen misslyckades."
    return 1
  fi
  ok "arduino-cli installerat"
}

ensure_core_installed() {
  local comp="$1"
  local core="${COMP_CORE[$comp]}"
  # Hantera @version-suffix
  local pkg="${core%%@*}"
  arduino-cli core update-index >/dev/null 2>&1 || true
  if ! arduino-cli core list | awk '{print $1}' | grep -qx "$pkg"; then
    log "Installerar core: $core"
    arduino-cli core install "$core"
  fi
  ok "Core $pkg redo"
}

# RP2040 core requires the board index URL
ensure_pico_index() {
  local cfg
  cfg="$(arduino-cli config dump 2>/dev/null)"
  if ! echo "$cfg" | grep -q "package_rp2040_index.json"; then
    log "Lägger till RP2040 board-URL"
    arduino-cli config set board_manager.additional_urls \
      https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json
    arduino-cli core update-index >/dev/null 2>&1 || true
  fi
}

compile_component() {
  local comp="$1"
  local fqbn="${COMP_FQBN[$comp]}"
  local sketch_name
  sketch_name="$(basename "${COMP_SRC[$comp]}" .ino)"
  local sketch_dir="$SKETCHBOOK/$sketch_name"

  log "Kompilerar $comp (FQBN: $fqbn)..."
  if comp_out="$(arduino-cli compile --fqbn "$fqbn" "$sketch_dir" 2>&1)"; then
    ok "Kompilering OK: $comp"
  else
    err "Kompilering misslyckades för $comp"
    echo "$comp_out" | tail -30
    return 1
  fi
}

# Skriv ut alla anslutna boards med port, namn och FQBN.
# Använder JSON-utdata från arduino-cli för robust parsning.
list_boards() {
  if ! command -v python3 >/dev/null 2>&1; then
    err "python3 krävs för 'list' (finns på macOS som standard)"
    return 1
  fi
  echo -e "${CYAN}Anslutna boards:${NC}"
  arduino-cli board list --format json 2>/dev/null | python3 - <<'PY'
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    print("  (kunde inte läsa board list)")
    sys.exit(0)
ports = data.get("ports", []) or data.get("detected_ports", [])
if not ports:
    print("  Inga anslutna boards.")
    sys.exit(0)
print(f"  {'Port':<28} {'Board Name':<28} {'FQBN':<48}")
print(f"  {'-'*28} {'-'*28} {'-'*48}")
for p in ports:
    port = p.get("address", {}).get("label") or p.get("port") or p.get("address", "")
    mb = p.get("matching_boards") or p.get("boards") or []
    if mb:
        name = mb[0].get("name", "?")
        fqbn = mb[0].get("fqbn", "?")
    else:
        name = "(okänd board)"
        fqbn = "(ingen FQBN detekterad)"
    print(f"  {str(port):<28} {str(name):<28} {str(fqbn):<48}")
PY
}

# Returnerar (via stdout) porten som matchar komponentens FQBN.
# Matchar board name om FQBN saknas (t.ex. UF2-bootloader-läge).
# Prioritering: explicit SHALLOT_PORT > FQBN-match > namn-match > ingen träff.
detect_port() {
  if [[ -n "${SHALLOT_PORT:-}" ]]; then
    echo "$SHALLOT_PORT"
    return
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    err "python3 krävs för portdetektion (finns på macOS som standard)"
    return 1
  fi

  local target_fqbn="${COMP_FQBN[$1]}"
  local target_name="${COMP_NAME[$1]}"

  local result
  result="$(arduino-cli board list --format json 2>/dev/null | python3 - "$target_fqbn" "$target_name" <<'PY'
import json, sys
fqbn_want = sys.argv[1] if len(sys.argv) > 1 else ""
ame_want  = sys.argv[2] if len(sys.argv) > 2 else ""
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ports = data.get("ports", []) or data.get("detected_ports", [])
# 1) exakt FQBN-match
for p in ports:
    mb = p.get("matching_boards") or p.get("boards") or []
    port = p.get("address", {}).get("label") or p.get("port") or p.get("address", "")
    for b in mb:
        if b.get("fqbn") == fqbn_want:
            print(port); sys.exit(0)
# 2) board name innehåller målnamnet (t.ex. "Feather RP2350", "Pico 2")
for p in ports:
    mb = p.get("matching_boards") or p.get("boards") or []
    port = p.get("address", {}).get("label") or p.get("port") or p.get("address", "")
    for b in mb:
        if name_want and name_want.lower() in (b.get("name", "") or "").lower():
            print(port); sys.exit(0)
PY
)"

  if [[ -n "$result" ]]; then
    echo "$result"
    return 0
  fi
  return 1
}

flash_component() {
  local comp="$1"
  local fqbn="${COMP_FQBN[$comp]}"
  local sketch_name
  sketch_name="$(basename "${COMP_SRC[$comp]}" .ino)"
  local sketch_dir="$SKETCHBOOK/$sketch_name"

  local port
  port="$(detect_port "$comp")"
  if [[ -z "$port" ]]; then
    err "Ingen ansluten board hittades som matchar $comp."
    err ""
    err "Anslut $comp via USB och försök igen, eller sätt port explicit:"
    err "  SHALLOT_PORT=/dev/cu.usbmodemXXXX ./sync-and-flash.sh $comp"
    err ""
    err "Lista alla anslutna boards med:"
    err "  ./sync-and-flash.sh list"
    return 1
  fi
  warn "Använder port: $port (matchad mot $comp)"
  log "Flashar $comp till $port ..."
  # UNO Q kräver inte UF2; Pico-boards flashas via arduino-cli upload.
  if flash_out="$(arduino-cli upload -p "$port" --fqbn "$fqbn" "$sketch_dir" 2>&1)"; then
    ok "Flashning OK: $comp @ $port"
  else
    err "Flashning misslyckades för $comp"
    echo "$flash_out" | tail -30
    return 1
  fi
}

# ----------------------------------------------------------------------------
# Huvudflöde
# ----------------------------------------------------------------------------

main() {
  local target="${1:-}"

  if [[ -z "$target" ]]; then
    echo "SHALLOT Sync & Flash"
    echo "Välj komponent:"
    echo "  1) PAW  (Adafruit Feather RP2350)"
    echo "  2) PLC  (Raspberry Pi Pico 2)"
    echo "  3) UNO Q (STM32U585)"
    echo "  4) Synka alla (ingen flashning)"
    echo "  q) Avbryt"
    read -r -p "Val: " choice
    case "$choice" in
      1) target="paw" ;;
      2) target="plc" ;;
      3) target="unoq" ;;
      4) target="sync" ;;
      q|Q) exit 0 ;;
      *) err "Ogiltigt val"; exit 1 ;;
    esac
  fi

  ensure_git
  ensure_repo
  checkout_branch

  if [[ "$target" == "sync" ]]; then
    sync_all
    ok "Klar. Alla skisser synkade till $SKETCHBOOK"
    exit 0
  fi

  if [[ -z "${COMP_SRC[$target]:-}" ]]; then
    err "Okänd komponent: $target (använd: paw | plc | unoq | sync)"
    exit 1
  fi

  sync_component "$target"

  if ! ensure_arduino_cli; then
    warn "arduino-cli saknas. Skisser är synkade — öppna i Arduino IDE för att flasha."
    exit 0
  fi

  # RP2040-cores (PAW + PLC) behöver extra board-URL
  if [[ "$target" == "paw" || "$target" == "plc" ]]; then
    ensure_pico_index
  fi
  ensure_core_installed "$target"

  if ! compile_component "$target"; then
    err "Kompilering misslyckades — avbryter innan flashning."
    exit 1
  fi

  flash_component "$target"
  ok "Klar!"
}

main "$@"
