#ifndef PAW_SESSION_H
#define PAW_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "ProvisioningProtocol.h"
#include "ShallotCrypto.h"

#define PAW_SESSION_PROVISION_TIMEOUT_MS 10000UL
#define PAW_SESSION_CHALLENGE_TIMEOUT_MS 30000UL
#define PAW_SESSION_GRANT_DISPLAY_MS 30000UL
#define PAW_SESSION_KEY_LEN PROV_KEY_LEN
#define PAW_SESSION_CHALLENGE_LEN 8
#define PAW_SESSION_FINGERPRINT_LEN (PROV_STORED_LEN - 1)

typedef enum {
    PAW_PROVISION_PENDING = 0,
    PAW_PROVISION_READY = 1,
    PAW_PROVISION_DONE = 2,
    PAW_PROVISION_FAILED = 3
} paw_provision_result_t;

typedef enum {
    PAW_SESSION_EVENT_NONE = 0,
    PAW_SESSION_EVENT_READY,
    PAW_SESSION_EVENT_STORED,
    PAW_SESSION_EVENT_ERROR,
    PAW_SESSION_EVENT_FAILED,
    PAW_SESSION_EVENT_CHALLENGE_ACCEPTED,
    PAW_SESSION_EVENT_CHALLENGE_TIMEOUT,
    PAW_SESSION_EVENT_AUTH_SUCCESS,
    PAW_SESSION_EVENT_AUTH_FAILURE,
    PAW_SESSION_EVENT_GRANT_EXPIRED,
    PAW_SESSION_EVENT_NO_KEY
} paw_session_event_t;

typedef enum {
    PAW_AUTH_WAITING_FOR_KEY = 0,
    PAW_AUTH_WAITING_FOR_CHALLENGE,
    PAW_AUTH_COMPUTING_RESPONSE,
    PAW_AUTH_WAITING_FOR_RESULT
} paw_auth_state_t;

typedef enum {
    PAW_AUTH_TRANSPORT_NONE = 0,
    PAW_AUTH_TRANSPORT_DOCK,
    PAW_AUTH_TRANSPORT_LORA
} paw_auth_transport_t;

typedef struct {
    uint8_t prov_phase;
    uint32_t prov_started_ms;
    uint8_t prov_buf[PROV_KEYDATA_LEN];
    uint8_t prov_got;
    uint8_t handshake_carry;
    bool handshake_carry_valid;
    uint8_t device_id[PROV_DEVICE_ID_LEN];
    uint8_t aes_key[SHALOT_KEY_LEN];
    uint8_t k_mac[SHALOT_KEY_LEN];
    uint8_t k_enc[SHALOT_KEY_LEN];
    bool key_stored;
    uint8_t fingerprint[PAW_SESSION_FINGERPRINT_LEN];
    paw_auth_state_t auth_state;
    paw_auth_transport_t auth_transport;
    uint8_t challenge[PAW_SESSION_CHALLENGE_LEN];
    bool challenge_valid;
    uint32_t challenge_at_ms;
    bool grant_displayed;
    uint32_t grant_at_ms;
} PawSession;

static inline bool paw_session_key_is_valid(const PawSession *session);

static inline void paw_session_clear_challenge(PawSession *session) {
    if (session == NULL) return;
    shalot_wipe(session->challenge, sizeof(session->challenge));
    session->challenge_valid = false;
}

static inline void paw_session_clear_grant(PawSession *session) {
    if (session == NULL) return;
    session->grant_displayed = false;
    session->grant_at_ms = 0;
}

static inline void paw_session_reset_auth(PawSession *session) {
    if (session == NULL) return;
    paw_session_clear_challenge(session);
    paw_session_clear_grant(session);
    session->auth_transport = PAW_AUTH_TRANSPORT_NONE;
    session->auth_state = paw_session_key_is_valid(session)
        ? PAW_AUTH_WAITING_FOR_CHALLENGE
        : PAW_AUTH_WAITING_FOR_KEY;
}

static inline void paw_session_reset(PawSession *session) {
    uint8_t device_id[PROV_DEVICE_ID_LEN];

    if (session == NULL) return;
    memcpy(device_id, session->device_id, sizeof(device_id));
    memset(session, 0, sizeof(*session));
    memcpy(session->device_id, device_id, sizeof(device_id));
    session->auth_state = PAW_AUTH_WAITING_FOR_KEY;
}

static inline void paw_session_wipe_key(PawSession *session) {
    if (session == NULL) return;
    shalot_wipe(session->aes_key, sizeof(session->aes_key));
    shalot_wipe(session->k_mac, sizeof(session->k_mac));
    shalot_wipe(session->k_enc, sizeof(session->k_enc));
    session->key_stored = false;
    shalot_wipe(session->fingerprint, sizeof(session->fingerprint));
    paw_session_reset_auth(session);
}

static inline void paw_session_init(PawSession *session,
                                    const uint8_t device_id[PROV_DEVICE_ID_LEN]) {
    if (session == NULL) return;
    memset(session, 0, sizeof(*session));
    if (device_id != NULL) {
        memcpy(session->device_id, device_id, PROV_DEVICE_ID_LEN);
    }
    session->auth_state = PAW_AUTH_WAITING_FOR_KEY;
}

static inline bool paw_session_key_is_valid(const PawSession *session) {
    if (session == NULL || !session->key_stored) return false;
    for (size_t i = 0; i < sizeof(session->aes_key); i++) {
        if (session->aes_key[i] != 0) return true;
    }
    return false;
}

static inline bool paw_session_has_key(const PawSession *session) {
    return session != NULL && session->key_stored;
}

static inline const uint8_t *paw_session_device_id(const PawSession *session) {
    return session == NULL ? NULL : session->device_id;
}

static inline const uint8_t *paw_session_k_mac(const PawSession *session) {
    return session == NULL ? NULL : session->k_mac;
}

static inline const uint8_t *paw_session_fingerprint(const PawSession *session) {
    return session == NULL ? NULL : session->fingerprint;
}

static inline const uint8_t *paw_session_challenge(const PawSession *session) {
    return session == NULL ? NULL : session->challenge;
}

static inline bool paw_session_challenge_is_valid(const PawSession *session) {
    return session != NULL && session->challenge_valid;
}

static inline paw_auth_state_t paw_session_auth_state(const PawSession *session) {
    return session == NULL ? PAW_AUTH_WAITING_FOR_KEY : session->auth_state;
}

static inline paw_auth_transport_t paw_session_auth_transport(
    const PawSession *session) {
    return session == NULL ? PAW_AUTH_TRANSPORT_NONE : session->auth_transport;
}

static inline void paw_session_abort(PawSession *session) {
    paw_session_reset_auth(session);
}

static inline paw_provision_result_t paw_session_provisioning_push(
    PawSession *session, uint8_t byte, uint32_t now_ms,
    paw_session_event_t *event) {
    uint8_t first;
    uint8_t second;
    uint32_t received_crc;
    uint32_t computed_crc;
    bool all_zero;
    uint8_t full_hash[SHALOT_SHA256_LEN];

    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL) return PAW_PROVISION_FAILED;

    if (session->prov_phase == 0) {
        if (session->handshake_carry_valid) {
            first = session->handshake_carry;
            second = byte;
            session->handshake_carry_valid = false;
        } else {
            session->handshake_carry = byte;
            session->handshake_carry_valid = true;
            return PAW_PROVISION_PENDING;
        }

        if (first == PROV_MSG_HANDSHAKE && second == PROV_TARGET_PAW) {
            paw_session_reset(session);
            session->prov_phase = 1;
            session->prov_started_ms = now_ms;
            if (event != NULL) *event = PAW_SESSION_EVENT_READY;
            return PAW_PROVISION_READY;
        }
        session->handshake_carry = byte;
        session->handshake_carry_valid = true;
        return PAW_PROVISION_PENDING;
    }

    if (session->prov_got < sizeof(session->prov_buf)) {
        session->prov_buf[session->prov_got++] = byte;
    }
    if (session->prov_got < sizeof(session->prov_buf)) {
        return PAW_PROVISION_PENDING;
    }

    if (session->prov_buf[0] != PROV_MSG_KEY_DATA ||
        session->prov_buf[1] != PROV_KEY_LEN) {
        paw_session_reset(session);
        if (event != NULL) *event = PAW_SESSION_EVENT_FAILED;
        return PAW_PROVISION_FAILED;
    }

    received_crc = ((uint32_t)session->prov_buf[18] << 24) |
                   ((uint32_t)session->prov_buf[19] << 16) |
                   ((uint32_t)session->prov_buf[20] << 8) |
                   (uint32_t)session->prov_buf[21];
    computed_crc = shalot_crc32(session->prov_buf + 2, PROV_KEY_LEN);
    if (computed_crc != received_crc) {
        paw_session_reset(session);
        if (event != NULL) *event = PAW_SESSION_EVENT_ERROR;
        return PAW_PROVISION_FAILED;
    }

    all_zero = true;
    for (size_t i = 0; i < PROV_KEY_LEN; i++) {
        if (session->prov_buf[2 + i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        paw_session_reset(session);
        if (event != NULL) *event = PAW_SESSION_EVENT_ERROR;
        return PAW_PROVISION_FAILED;
    }

    memcpy(session->aes_key, session->prov_buf + 2, PROV_KEY_LEN);
    session->key_stored = true;
    shalot_derive_k_mac(session->aes_key, session->k_mac);
    shalot_derive_k_enc(session->aes_key, session->k_enc);
    shalot_sha256(session->aes_key, PROV_KEY_LEN, full_hash);
    memcpy(session->fingerprint, full_hash, PAW_SESSION_FINGERPRINT_LEN);
    shalot_wipe(full_hash, sizeof(full_hash));
    shalot_wipe(session->prov_buf, sizeof(session->prov_buf));
    session->prov_got = 0;
    session->prov_phase = 0;
    session->handshake_carry_valid = false;
    paw_session_reset_auth(session);
    if (event != NULL) *event = PAW_SESSION_EVENT_STORED;
    return PAW_PROVISION_DONE;
}

static inline paw_provision_result_t paw_session_provisioning_poll(
    PawSession *session, uint32_t now_ms, paw_session_event_t *event) {
    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL) return PAW_PROVISION_FAILED;
    if (session->prov_phase != 1 ||
        session->prov_got >= sizeof(session->prov_buf) ||
        now_ms - session->prov_started_ms <= PAW_SESSION_PROVISION_TIMEOUT_MS) {
        return PAW_PROVISION_PENDING;
    }

    paw_session_reset(session);
    if (event != NULL) *event = PAW_SESSION_EVENT_FAILED;
    return PAW_PROVISION_FAILED;
}

static inline bool paw_session_accept_challenge(
    PawSession *session, paw_auth_transport_t transport,
    const uint8_t *challenge, size_t challenge_len,
    uint32_t now_ms, paw_session_event_t *event) {
    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL || challenge == NULL ||
        challenge_len != PAW_SESSION_CHALLENGE_LEN ||
        (transport != PAW_AUTH_TRANSPORT_DOCK &&
         transport != PAW_AUTH_TRANSPORT_LORA)) {
        return false;
    }
    if (!paw_session_key_is_valid(session)) {
        paw_session_reset_auth(session);
        if (event != NULL) *event = PAW_SESSION_EVENT_NO_KEY;
        return false;
    }
    if (session->auth_state != PAW_AUTH_WAITING_FOR_CHALLENGE ||
        session->auth_transport != PAW_AUTH_TRANSPORT_NONE) {
        return false;
    }

    memcpy(session->challenge, challenge, PAW_SESSION_CHALLENGE_LEN);
    session->challenge_valid = true;
    session->challenge_at_ms = now_ms;
    session->auth_transport = transport;
    session->auth_state = PAW_AUTH_COMPUTING_RESPONSE;
    if (event != NULL) *event = PAW_SESSION_EVENT_CHALLENGE_ACCEPTED;
    return true;
}

static inline bool paw_session_response_sent(
    PawSession *session, paw_auth_transport_t transport) {
    if (session == NULL || session->auth_state != PAW_AUTH_COMPUTING_RESPONSE ||
         !session->challenge_valid || session->auth_transport != transport) {
        return false;
    }
    paw_session_clear_challenge(session);
    session->auth_state = PAW_AUTH_WAITING_FOR_RESULT;
    return true;
}

static inline bool paw_session_on_result(PawSession *session,
                                         paw_auth_transport_t transport,
                                         bool success, uint32_t now_ms,
                                         paw_session_event_t *event) {
    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL || session->auth_state != PAW_AUTH_WAITING_FOR_RESULT ||
        session->auth_transport != transport) {
        return false;
    }

    session->auth_state = PAW_AUTH_WAITING_FOR_CHALLENGE;
    session->auth_transport = PAW_AUTH_TRANSPORT_NONE;
    paw_session_clear_grant(session);
    if (success) {
        session->grant_displayed = true;
        session->grant_at_ms = now_ms;
        if (event != NULL) *event = PAW_SESSION_EVENT_AUTH_SUCCESS;
    } else if (event != NULL) {
        *event = PAW_SESSION_EVENT_AUTH_FAILURE;
    }
    return true;
}

static inline bool paw_session_no_key(PawSession *session,
                                      paw_session_event_t *event) {
    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL || session->auth_state != PAW_AUTH_COMPUTING_RESPONSE) {
        return false;
    }
    paw_session_reset_auth(session);
    if (event != NULL) *event = PAW_SESSION_EVENT_NO_KEY;
    return true;
}

static inline bool paw_session_challenge_timeout(
    PawSession *session, uint32_t now_ms, paw_session_event_t *event) {
    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL ||
        (session->auth_state != PAW_AUTH_COMPUTING_RESPONSE &&
         session->auth_state != PAW_AUTH_WAITING_FOR_RESULT) ||
        now_ms - session->challenge_at_ms <= PAW_SESSION_CHALLENGE_TIMEOUT_MS) {
        return false;
    }

    paw_session_reset_auth(session);
    if (event != NULL) *event = PAW_SESSION_EVENT_CHALLENGE_TIMEOUT;
    return true;
}

static inline bool paw_session_grant_expired(PawSession *session,
                                             uint32_t now_ms,
                                             paw_session_event_t *event) {
    if (event != NULL) *event = PAW_SESSION_EVENT_NONE;
    if (session == NULL || !session->grant_displayed ||
        now_ms - session->grant_at_ms <= PAW_SESSION_GRANT_DISPLAY_MS) {
        return false;
    }

    paw_session_clear_grant(session);
    if (event != NULL) *event = PAW_SESSION_EVENT_GRANT_EXPIRED;
    return true;
}

#endif
