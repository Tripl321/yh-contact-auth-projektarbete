/* Host behavior harness for libraries/PawSession/src/PawSession.h.
 *
 * Compiled and run on host (cc -std=c99). Each CHECK prints PASS/FAIL and
 * main() returns nonzero if any scenario failed. No Serial/radio/e-paper
 * dependencies: exercises only the transport-free state machine.
 *
 * Usage: paw_session_host   (prints PASS/FAIL lines, exit code = summary)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "PawSession.h"

static const uint8_t devId[PROV_DEVICE_ID_LEN] = {0x50, 0x41, 0x57, 0x01};

static int g_failures = 0;

#define CHECK(cond, name)                                      \
    do {                                                        \
        if (cond) {                                             \
            printf("PASS %s\n", (name));                        \
        } else {                                                \
            printf("FAIL %s\n", (name));                        \
            g_failures++;                                       \
        }                                                       \
    } while (0)

static void store_valid_key(PawSession *s, uint32_t t0) {
    paw_session_init(s, devId);
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i + 1);
    uint8_t pkt[PROV_KEYDATA_LEN];
    prov_build_key_data(pkt, key);
    paw_session_event_t e;
    paw_session_provisioning_push(s, PROV_MSG_HANDSHAKE, t0, &e);
    paw_session_provisioning_push(s, PROV_TARGET_PAW, t0, &e);
    for (size_t i = 0; i < PROV_KEYDATA_LEN; i++) {
        paw_session_provisioning_push(s, pkt[i], t0 + i, &e);
    }
}

int main(void) {
    uint8_t nonce[PAW_SESSION_CHALLENGE_LEN];
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(0x10 + i);

    /* init: no key, state waiting for key */
    PawSession s;
    paw_session_init(&s, devId);
    CHECK(!paw_session_key_is_valid(&s), "init: no key valid");
    CHECK(paw_session_auth_state(&s) == PAW_AUTH_WAITING_FOR_KEY, "init: waiting for key");
    CHECK(paw_session_auth_transport(&s) == PAW_AUTH_TRANSPORT_NONE, "init: no transport");
    CHECK(paw_session_device_id(&s) != NULL, "init: device id retained");
    CHECK(memcmp(paw_session_device_id(&s), devId, PROV_DEVICE_ID_LEN) == 0, "init: device id preserved");
    CHECK(!paw_session_challenge_is_valid(&s), "init: no challenge");

    /* provisioning: handshake carries READY, keydata stores */
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i + 1);
    uint8_t pkt[PROV_KEYDATA_LEN];
    prov_build_key_data(pkt, key);
    paw_session_event_t e;
    paw_provision_result_t r;
    r = paw_session_provisioning_push(&s, PROV_MSG_HANDSHAKE, 0, &e);
    CHECK(r == PAW_PROVISION_PENDING && e == PAW_SESSION_EVENT_NONE, "prov: first handshake byte pending");
    r = paw_session_provisioning_push(&s, PROV_TARGET_PAW, 0, &e);
    CHECK(r == PAW_PROVISION_READY && e == PAW_SESSION_EVENT_READY, "prov: handshake READY");
    for (size_t i = 0; i < PROV_KEYDATA_LEN; i++) {
        r = paw_session_provisioning_push(&s, pkt[i], 10 + i, &e);
    }
    CHECK(r == PAW_PROVISION_DONE && e == PAW_SESSION_EVENT_STORED, "prov: key stored");
    CHECK(paw_session_key_is_valid(&s), "prov: key valid after store");
    CHECK(paw_session_auth_state(&s) == PAW_AUTH_WAITING_FOR_CHALLENGE, "prov: waiting challenge after store");
    const uint8_t *fp = paw_session_fingerprint(&s);
    CHECK(fp != NULL && (fp[0] != 0 || fp[1] != 0 || fp[2] != 0 || fp[3] != 0), "prov: nonzero fingerprint");

    /* zero key rejected, no state change that grants auth */
    PawSession z;
    paw_session_init(&z, devId);
    uint8_t zerok[16] = {0};
    uint8_t zpkt[PROV_KEYDATA_LEN];
    prov_build_key_data(zpkt, zerok);
    paw_session_provisioning_push(&z, PROV_MSG_HANDSHAKE, 0, &e);
    paw_session_provisioning_push(&z, PROV_TARGET_PAW, 0, &e);
    for (size_t i = 0; i < PROV_KEYDATA_LEN; i++) {
        r = paw_session_provisioning_push(&z, zpkt[i], 10 + i, &e);
    }
    CHECK(r == PAW_PROVISION_FAILED && e == PAW_SESSION_EVENT_ERROR, "zero-key: rejected");
    CHECK(!paw_session_key_is_valid(&z), "zero-key: not stored");

    /* CRC mismatch rejected */
    PawSession c;
    paw_session_init(&c, devId);
    uint8_t badpkt[PROV_KEYDATA_LEN];
    prov_build_key_data(badpkt, key);
    badpkt[PROV_KEYDATA_LEN - 1] ^= 0xFF; /* break CRC */
    paw_session_provisioning_push(&c, PROV_MSG_HANDSHAKE, 0, &e);
    paw_session_provisioning_push(&c, PROV_TARGET_PAW, 0, &e);
    for (size_t i = 0; i < PROV_KEYDATA_LEN; i++) {
        r = paw_session_provisioning_push(&c, badpkt[i], 10 + i, &e);
    }
    CHECK(r == PAW_PROVISION_FAILED && e == PAW_SESSION_EVENT_ERROR, "crc: rejected");
    CHECK(!paw_session_key_is_valid(&c), "crc: no key stored");

    /* malformed tag/length rejected */
    PawSession m;
    paw_session_init(&m, devId);
    uint8_t badtag[PROV_KEYDATA_LEN];
    prov_build_key_data(badtag, key);
    badtag[0] = 0x00; /* wrong tag */
    paw_session_provisioning_push(&m, PROV_MSG_HANDSHAKE, 0, &e);
    paw_session_provisioning_push(&m, PROV_TARGET_PAW, 0, &e);
    for (size_t i = 0; i < PROV_KEYDATA_LEN; i++) {
        r = paw_session_provisioning_push(&m, badtag[i], 10 + i, &e);
    }
    CHECK(r == PAW_PROVISION_FAILED && e == PAW_SESSION_EVENT_FAILED, "malformed: rejected");
    CHECK(!paw_session_key_is_valid(&m), "malformed: no key");

    /* provisioning timeout wipes partial + clears any prior key */
    PawSession t;
    store_valid_key(&t, 0);
    CHECK(paw_session_key_is_valid(&t), "timeout: key before");
    /* new handshake should clear previous key (fail-closed reset) */
    paw_session_provisioning_push(&t, PROV_MSG_HANDSHAKE, 1000, &e);
    CHECK(e == PAW_SESSION_EVENT_NONE, "timeout: first handshake byte pending");
    paw_session_provisioning_push(&t, PROV_TARGET_PAW, 1000, &e);
    CHECK(e == PAW_SESSION_EVENT_READY, "timeout: new handshake READY");
    CHECK(!paw_session_key_is_valid(&t), "timeout: prior key cleared on new handshake");
    /* push one partial key byte then let the poll timer fire */
    paw_session_provisioning_push(&t, pkt[0], 1010, &e);
    r = paw_session_provisioning_poll(&t, 1010 + PAW_SESSION_PROVISION_TIMEOUT_MS + 1, &e);
    CHECK(r == PAW_PROVISION_FAILED && e == PAW_SESSION_EVENT_FAILED, "timeout: fires");
    CHECK(!paw_session_key_is_valid(&t), "timeout: no key after timeout");

    /* challenge without a key: NO_KEY, state unchanged */
    PawSession nk;
    paw_session_init(&nk, devId);
    paw_session_event_t ne;
    bool ok = paw_session_accept_challenge(&nk, PAW_AUTH_TRANSPORT_DOCK,
                                           nonce, sizeof(nonce), 0, &ne);
    CHECK(!ok && ne == PAW_SESSION_EVENT_NO_KEY, "no-key: challenge rejected");
    CHECK(paw_session_auth_transport(&nk) == PAW_AUTH_TRANSPORT_NONE, "no-key: no transport bound");

    /* challenge length validation: only exactly PAW_SESSION_CHALLENGE_LEN */
    PawSession cv;
    store_valid_key(&cv, 0);
    bool badlen = paw_session_accept_challenge(&cv, PAW_AUTH_TRANSPORT_DOCK,
                                               nonce, sizeof(nonce) - 1, 1, &e);
    CHECK(!badlen, "challenge: wrong length rejected");
    /* duplicate challenge while already computing is rejected (state-gated) */
    bool dup = paw_session_accept_challenge(&cv, PAW_AUTH_TRANSPORT_DOCK,
                                            nonce, sizeof(nonce), 1, &e);
    CHECK(dup && e == PAW_SESSION_EVENT_CHALLENGE_ACCEPTED, "challenge: accepted when waiting");
    bool dup2 = paw_session_accept_challenge(&cv, PAW_AUTH_TRANSPORT_LORA,
                                             nonce, sizeof(nonce), 1, &e);
    CHECK(!dup2 && e == PAW_SESSION_EVENT_NONE, "challenge: duplicate rejected");

    /* response_sent consumes the challenge and arms waiting-for-result */
    CHECK(paw_session_challenge_is_valid(&cv), "response: challenge valid before sent");
    CHECK(paw_session_response_sent(&cv, PAW_AUTH_TRANSPORT_DOCK), "response: sent transitions");
    CHECK(!paw_session_challenge_is_valid(&cv), "response: challenge cleared after sent");
    CHECK(paw_session_auth_state(&cv) == PAW_AUTH_WAITING_FOR_RESULT, "response: waiting for result");

    /* on_result: success grants; transport must match */
    bool g = paw_session_on_result(&cv, PAW_AUTH_TRANSPORT_DOCK, true, 2000, &e);
    CHECK(g && e == PAW_SESSION_EVENT_AUTH_SUCCESS, "result: success grants");
    CHECK(paw_session_auth_state(&cv) == PAW_AUTH_WAITING_FOR_CHALLENGE, "result: back to waiting challenge");

    /* grant expiry reverts */
    bool ge = paw_session_grant_expired(&cv, 2000 + PAW_SESSION_GRANT_DISPLAY_MS + 1, &e);
    CHECK(ge && e == PAW_SESSION_EVENT_GRANT_EXPIRED, "grant: expiry fires");

    /* unsolicited result is ignored */
    bool ignored = paw_session_on_result(&cv, PAW_AUTH_TRANSPORT_DOCK, true, 3000, &e);
    CHECK(!ignored && e == PAW_SESSION_EVENT_NONE, "result: unsolicited ignored");

    /* transport mismatch on result is ignored */
    PawSession tv;
    store_valid_key(&tv, 0);
    paw_session_accept_challenge(&tv, PAW_AUTH_TRANSPORT_LORA, nonce, sizeof(nonce), 1, &e);
    paw_session_response_sent(&tv, PAW_AUTH_TRANSPORT_LORA);
    bool mis = paw_session_on_result(&tv, PAW_AUTH_TRANSPORT_DOCK, true, 2000, &e);
    CHECK(!mis, "result: transport mismatch ignored");

    /* challenge timeout while computing resets auth to waiting challenge */
    PawSession ct;
    store_valid_key(&ct, 0);
    paw_session_accept_challenge(&ct, PAW_AUTH_TRANSPORT_DOCK, nonce, sizeof(nonce), 1, &e);
    bool cto = paw_session_challenge_timeout(&ct, 1 + PAW_SESSION_CHALLENGE_TIMEOUT_MS + 1, &e);
    CHECK(cto && e == PAW_SESSION_EVENT_CHALLENGE_TIMEOUT, "timeout: challenge timeout fires");
    CHECK(paw_session_auth_state(&ct) == PAW_AUTH_WAITING_FOR_CHALLENGE, "timeout: auth reset, key retained");

    /* challenge timeout does nothing while idle (no outstanding challenge) */
    PawSession wt;
    store_valid_key(&wt, 0);
    bool notimed = paw_session_challenge_timeout(&wt, 1000, &e);
    CHECK(!notimed, "timeout: no timeout when idle");

    /* wipe_key clears material + auth, retains device id */
    PawSession w;
    paw_session_init(&w, devId);
    store_valid_key(&w, 0);
    CHECK(paw_session_key_is_valid(&w), "wipe: key before");
    paw_session_wipe_key(&w);
    CHECK(!paw_session_key_is_valid(&w), "wipe: key cleared");
    CHECK(paw_session_auth_transport(&w) == PAW_AUTH_TRANSPORT_NONE, "wipe: transport cleared");
    CHECK(memcmp(paw_session_device_id(&w), devId, PROV_DEVICE_ID_LEN) == 0, "wipe: device id retained");

    /* abort clears transport but retains key */
    PawSession ab;
    paw_session_init(&ab, devId);
    store_valid_key(&ab, 0);
    paw_session_accept_challenge(&ab, PAW_AUTH_TRANSPORT_DOCK, nonce, sizeof(nonce), 1, &e);
    paw_session_response_sent(&ab, PAW_AUTH_TRANSPORT_DOCK);
    CHECK(paw_session_auth_transport(&ab) != PAW_AUTH_TRANSPORT_NONE, "abort: transport before");
    paw_session_abort(&ab);
    CHECK(paw_session_key_is_valid(&ab), "abort: key retained");
    CHECK(paw_session_auth_transport(&ab) == PAW_AUTH_TRANSPORT_NONE, "abort: transport cleared");

    /* null-safety: abort on NULL must not crash */
    paw_session_abort(NULL);
    CHECK(1, "abort: null-safe");

    if (g_failures) {
        printf("SUMMARY: %d failed\n", g_failures);
        return 1;
    }
    printf("SUMMARY: all paw_session scenarios passed\n");
    return 0;
}
