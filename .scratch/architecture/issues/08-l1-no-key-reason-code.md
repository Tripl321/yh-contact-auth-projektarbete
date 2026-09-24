# 08 — LOW: L1 — DenKey invalid reason code leaks key status

**What to build:** When `den_key_valid()` returns false (no key provisioned or corrupt key),
`den_on_response()` maps to `DEN_REASON_HMAC_MISMATCH` instead of a dedicated reason code.
This leaks whether a key is provisioned through the non-secret USB-observable reason code.

**Current code:** `plc/den-main/den-main.ino:846-848`
```c
if (!den_key_valid()) {
    den_fail(DEN_REASON_HMAC_MISMATCH);  // should be DEN_REASON_NO_KEY
    return;
}
```

**Proposed mitigation:** Add `DEN_REASON_NO_KEY = 12` to the `DenReason` enum and use it
in the `den_key_valid()` failure path. Reason codes are non-secret, but a dedicated code
is clearer for ops and avoids implying the key was present but the MAC was wrong.

**Priority:** low — no security impact beyond operational clarity.

**Blocked by:** None.

**Status:** pending

- [ ] Add `DEN_REASON_NO_KEY = 12` to `DenReason` enum
- [ ] Update `den_on_response` to use `DEN_REASON_NO_KEY` instead of `DEN_REASON_HMAC_MISMATCH`
- [ ] Update reason code table in `docs/13-pro-53-fail-closed.md` §2
- [ ] Add test asserting NO_KEY reason code on unprovisioned DEN
