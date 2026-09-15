#!/bin/bash
#
# flash-paw-remote.sh — Build + flash PAW firmware via MamaBear over Tailscale
#
# Flöde:
#   1. Bygg UF2 lokalt med arduino-cli
#   2. Kopiera UF2 till MamaBear via SCP (över Tailscale)
#   3. SSH:a in på MamaBear och flasha PAW via picotool eller BOOTSEL
#
# Säkerhet:
#   - Använder endast SSH-alias från ~/.ssh/config (aldrig rå IP eller user@)
#   - BatchMode=yes (ingen lösenordsinteraktion)
#   - Fail-closed: exit koden 1 vid vilket fel
#
# Krav:
#   - arduino-cli + rp2040:rp2040 core installerade lokalt
#   - SSH-alias "mamabear" i ~/.ssh/config (Tailscale)
#   - PAW (Adafruit Feather RP2350) ansluten till MamaBear via USB

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UF2_DIR="$SCRIPT_DIR/build"
UF2_FILE="$UF2_DIR/paw-main.ino.uf2"
REMOTE_HOST="${MAMABEAR_HOST:-mamabear}"
REMOTE_PATH="/tmp/paw-main.uf2"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()  { echo -e "${GREEN}✓${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*" >&2; }
warn() { echo -e "${YELLOW}!${NC} $*"; }

validate_alias() {
    local alias="$1"
    if [[ "$alias" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
       [[ "$alias" =~ ^[0-9a-fA-F:]+$ ]]; then
        err "Alias ser ut som en IP-adress — använd ett SSH-alias från ~/.ssh/config"
        return 1
    fi
    if [[ "$alias" == *"="* ]] || [[ "$alias" == *" "* ]] || [[ "$alias" == *"@"* ]]; then
        err "Ogiltigt SSH-alias: $alias"
        return 1
    fi
    return 0
}

remote_cmd() {
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE_HOST" "$@"
}

remote_scp() {
    scp -o BatchMode=yes -o ConnectTimeout=10 "$1" "$REMOTE_HOST:$2"
}

step_build() {
    log "Steg 1: Bygg PAW firmware (UF2)"
    mkdir -p "$UF2_DIR"
    if ! command -v arduino-cli &>/dev/null; then
        err "arduino-cli saknas — installera först"
        return 1
    fi
    (
        cd "$PROJECT_ROOT"
        arduino-cli compile \
          --fqbn rp2040:rp2040:adafruit_feather_rp2350_hstx \
          --build-property build.extra_flags="-DARDUINO_USB_CDC_ONLY" \
          --libraries libraries \
          --output-dir "$UF2_DIR" \
          "$SCRIPT_DIR/paw-main.ino"
    )
    if [[ ! -f "$UF2_FILE" ]]; then
        err "BuildMisslyckades — ingen UF2-fil hittades"
        return 1
    fi
    ok "UF2 byggd: $UF2_FILE ($(du -h "$UF2_FILE" | cut -f1))"
}

step_copy() {
    log "Steg 2: Kopiera UF2 till $REMOTE_HOST"
    remote_scp "$UF2_FILE" "$REMOTE_PATH"
    local size
    size=$(remote_cmd "stat -c%s $REMOTE_PATH")
    ok "UF2 kopierad till $REMOTE_HOST:$REMOTE_PATH ($size bytes)"
}

step_flash() {
    log "Steg 3: Flasha PAW på $REMOTE_HOST"
    remote_cmd "ls $REMOTE_PATH" || { err "UF2-fil saknas på MamaBear"; return 1; }

    # Försök picotool först (renaste API)
    if remote_cmd "command -v picotool" 2>/dev/null; then
        log "Använder picotool för flashning"
        remote_cmd "sudo picotool load -x $REMOTE_PATH" || {
            err "picotool misslyckades — försök BOOTSEL-manuellt"
            return 1
        }
        ok "PAW flashad via picotool"
        return 0
    fi

    # Fallback: BOOTSEL drag-and-drop via mount
    warn "picotool saknas — använder BOOTSEL-metoden"
    warn "Fysiskt steg: håll BOOTSEL på PAW, anslut USB till MamaBear, släpp BOOTSEL"
    remote_cmd "
        set -e
        # Vänta på att RPI-RP2 ska monteras
        echo 'Väntar på RPI-RP2-enhet...'
        for i in \$(seq 1 30); do
            if lsblk -no NAME,TYPE,MOUNTPOINT | grep -q 'part.*RPI-RP2'; then
                break
            fi
            sleep 1
        done
        MOUNT_POINT=\$(lsblk -no NAME,MOUNTPOINT | awk '/RPI-RP2/ {print \$1}' | xargs -I{} findmnt -n -o TARGET /dev/{} 2>/dev/null || echo '')
        if [[ -z \"\$MOUNT_POINT\" ]]; then
            # Försök standardmontering
            MOUNT_POINT=/tmp/rp2_paw
            mkdir -p \"\$MOUNT_POINT\"
            sudo mount /dev/sda1 \"\$MOUNT_POINT\" || { echo 'Kan inte montera RPI-RP2'; exit 1; }
        fi
        cp $REMOTE_PATH \"\$MOUNT_POINT/paw-main.uf2\"
        sync
        sudo umount \"\$MOUNT_POINT\"
        echo 'Flashning klar — PAW startas om automatiskt'
    " || { err "BOOTSEL-flashning misslyckades"; return 1; }
    ok "PAW flashad via UF2BOOTSEL"
}

step_verify() {
    log "Steg 4: Verifiera (lässerie — 115200 baud)"
    remote_cmd "timeout 5 cat /dev/ttyACM0 -b 115200 2>/dev/null || true" || warn "Ingen seriell output (PAW kan inte ha USB-serial)"
}

main() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}PAW Remote Flash via MamaBear (Tailscale)${NC}"
    echo -e "${CYAN}============================================${NC}"

    validate_alias "$REMOTE_HOST" || exit 1

    log "SSH-alias: $REMOTE_HOST"
    log "Verifcar åtkomst till $REMOTE_HOST..."
    if ! remote_cmd "echo OK" >/dev/null 2>&1; then
        err "Kan inte nå $REMOTE_HOST via SSH — kontrollera Tailscale och ~/.ssh/config"
        exit 1
    fi
    ok "Förbindelse till $REMOTE_HOST etablerad"

    step_build || exit 1
    step_copy || exit 1
    step_flash || exit 1
    step_verify

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}PAW flashning klar!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo "  firmware: $UF2_FILE"
    echo "  host:     $REMOTE_HOST"
    echo ""
    echo "Fysisk verifiering:"
    echo "  - e-Paper visar AUTHENTICATING (tre punkter i triangel)"
    echo "  - LED: snabb blinkning (väntar på nyckel)"
    echo "  - Serial: [PRO-48] Waiting for key distribution from UNO Q..."
}

main "$@"
