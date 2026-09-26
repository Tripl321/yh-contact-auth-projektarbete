# 09 — LOW: L2 — Blocklist fingerprint comparison not constant-time

**What to build:** Blocklist fingerprint comparison in `den_on_response()` uses a sequential
XOR-loop that is not constant-time. While the information leak is minimal (4-byte
fingerprints, max 16 entries), this does not follow the codebase convention of
constant-time comparison for secret-derived values.

**Current code:** `plc/den-main/den-main.ino:900-906`

```c
for (uint8_t i = 0; i < current_blocklist.entry_count; i++) {
    uint8_t diff = 0;
    for (uint8_t j = 0; j < KEY_HASH_SIZE; j++) {
        diff |= (uint8_t)(fp[j] ^ current_blocklist.entries[i][j]);
    }
    if (diff == 0) { blocked = 1; break; }
}
```

**Proposed mitigation:** Use `den_ct_compare()` from `libraries/DenUartProtocol` for the
4-byte fingerprint comparison within each blocklist entry. The early-exit on match
(`if (diff == 0) { blocked = 1; break; }`) is acceptable: the outer loop position does
not itself reveal which entry matched (all entries are checked in the denial case).

**Priority:** low — the fingerprint is derived from the shared key but is only 4 bytes,
and the blocklist is sent over authenticated provisioning (PRO-46), not the public
challenge-response channel. Timing attack requires local serial access.

**Blocked by:** None.

**Status:** pending

- [ ] Replace inner XOR loop with `den_ct_compare(fp, entry, KEY_HASH_SIZE)`
- [ ] Add source guard test asserting no manual XOR-compare on fingerprints
- [ ] Note: outer loop early-exit is acceptable (denial path checks all entries)
