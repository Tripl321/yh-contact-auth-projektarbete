# 07 — PRO-98: Build-time Ed25519 trust root pinning (fail-closed)

**What to build:** Replace the all-zeros blocklist public key placeholder in DEN firmware with a
compile-time configurable trust root that defaults to fail-closed (all-zeros = deny all) and
requires explicit pinning for production builds.

**Changes implemented:**

- `plc/den-main/den-main.ino`: `#ifdef SHALLOT_BLOCKLIST_PUBKEY` → use build-flag bytes;
  `#else` → all-zeros fail-closed default; `#error` via `SHALLOT_BLOCKLIST_REQUIRE_KEY`
  when the production key is missing; added `blocklist_trust_root_pinned()` runtime helper;
  boot-time USB-serial status log.
- `tests/test_pro88_den.py`: +11 tests (build-config guards, fail-closed default,
  valid-blocklist acceptance, blocked-fp denial, empty-list acceptance, missing-list
  denial, invalid signature rejection, replay rejection, HMAC-before-gate, deny-chain).
- `tests/test_pro98_den_blocklist.py`: replaced `test_pro98_source_trust_root_placeholder_scoped`
  with `test_pro98_source_trust_root_build_configurable`.
- `docs/17-pro-98-paw-blocklist.md`: updated §7, §9, §11.2, §11.4, §11.6.
- `docs/09-integrationsbeskrivning.md`: statusmatris updated (562 tests, pinning).
- `docs/13-pro-53-fail-closed.md`: testcounts updated to 562.

**Production build command:**

```bash
arduino-cli compile -e \
  -DSHALLOT_BLOCKLIST_PUBKEY='0x01,0x02,...,0x20' \
  -DSHALLOT_BLOCKLIST_REQUIRE_KEY \
  plc/den-main
```

**CI guard:** Production CI pipeline defines `SHALLOT_BLOCKLIST_REQUIRE_KEY`; without
`SHALLOT_BLOCKLIST_PUBKEY` the build fails with `#error`.

**Blocking risk:** Trust root still all-zeros by default → no blocklist activates → all
PAWs denied at the revocation gate. Production deployment requires pinning a real key.

**Blocked by:** None.

**Status:** done

- [x] Build-time pinning implemented in firmware
- [x] Fail-closed default (all-zeros) preserved
- [x] CI guard (`#error` on missing key) implemented
- [x] Runtime helper `blocklist_trust_root_pinned()` added
- [x] 11 new tests added and passing
- [x] Documentation updated (docs/17 §11.2, §11.4, §11.6)
- [x] Full suite: 562 passed in 5.82s
