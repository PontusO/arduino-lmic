/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C crypto backend -- LoRaWAN key storage and cryptographic operations.
 *
 * Implements the SE backend API (join request/accept, MIC, AES-CTR, session
 * key derivation) using LMIC's built-in AES engine.  The ATECC608C chip is
 * used for hardware random number generation via a registered callback;
 * a software xorshift32 fallback is used if no hardware RNG is registered.
 *
 *******************************************************************************/

#ifndef _atecc608c_backend_h_
#define _atecc608c_backend_h_

#include <stdint.h>
#include <stdbool.h>

/* SE interface types: LMIC_SecureElement_JoinFormat_t, KeySelector_t, etc. */
#include "../../i/lmic_secure_element_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum atecc608c_backend_status_e {
    ATECC608C_BACKEND_STATUS_OK = 0,
    ATECC608C_BACKEND_STATUS_INVALID_PARAM,
    ATECC608C_BACKEND_STATUS_NOT_INITIALIZED,
    ATECC608C_BACKEND_STATUS_NOT_PROVISIONED,
    ATECC608C_BACKEND_STATUS_PERMISSION,
    ATECC608C_BACKEND_STATUS_UNSUPPORTED,
    ATECC608C_BACKEND_STATUS_IO_ERROR,
    ATECC608C_BACKEND_STATUS_CRYPTO_ERROR,
} atecc608c_backend_status_t;

typedef struct atecc608c_backend_ctx_s {
    bool initialized;
    bool appkey_present;
    bool appkey_readable;
    bool appeui_present;
    bool deveui_present;
    bool nwkskey_present[5];
    bool appskey_present[5];

    uint8_t appkey[16];
    uint8_t appeui[8];
    uint8_t deveui[8];
    uint8_t nwkskey[5][16];
    uint8_t appskey[5][16];

    /*
     * Optional hardware RNG hook.  When set, backend_random() calls this
     * instead of the built-in xorshift32 PRNG.  len is always in [1, 32].
     * Returns true on success, false on I/O error.
     */
    bool (*hw_random)(uint8_t *out, uint8_t len, void *ctx);
    void *hw_random_ctx;
} atecc608c_backend_ctx_t;

/* lifecycle */
atecc608c_backend_status_t atecc608c_backend_init(atecc608c_backend_ctx_t *ctx);

/*
 * Register a hardware RNG function.  When set, atecc608c_backend_random() calls
 * fn(out, len, user_ctx) to fill up to 32 bytes at a time.  Pass NULL to revert
 * to the built-in software PRNG.
 */
void atecc608c_backend_set_hw_random(atecc608c_backend_ctx_t *ctx,
                                      bool (*fn)(uint8_t *out, uint8_t len, void *user_ctx),
                                      void *user_ctx);

/* randomness */
atecc608c_backend_status_t atecc608c_backend_random(atecc608c_backend_ctx_t *ctx, uint8_t *buf, uint8_t len);

/* root credentials */
atecc608c_backend_status_t atecc608c_backend_set_appkey(atecc608c_backend_ctx_t *ctx, const uint8_t key[16]);
atecc608c_backend_status_t atecc608c_backend_get_appkey(atecc608c_backend_ctx_t *ctx, uint8_t key[16]);

atecc608c_backend_status_t atecc608c_backend_set_appeui(atecc608c_backend_ctx_t *ctx, const uint8_t eui[8]);
atecc608c_backend_status_t atecc608c_backend_get_appeui(atecc608c_backend_ctx_t *ctx, uint8_t eui[8]);

atecc608c_backend_status_t atecc608c_backend_set_deveui(atecc608c_backend_ctx_t *ctx, const uint8_t eui[8]);
atecc608c_backend_status_t atecc608c_backend_get_deveui(atecc608c_backend_ctx_t *ctx, uint8_t eui[8]);

/* session credentials */
atecc608c_backend_status_t atecc608c_backend_set_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16]);
atecc608c_backend_status_t atecc608c_backend_get_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16]);

atecc608c_backend_status_t atecc608c_backend_set_appskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16]);
atecc608c_backend_status_t atecc608c_backend_get_appskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16]);

/* crypto hooks - stub now, real later */
atecc608c_backend_status_t atecc608c_backend_create_join_request(
    atecc608c_backend_ctx_t *ctx,
    uint8_t join_request[23],
    uint8_t join_format
);

atecc608c_backend_status_t atecc608c_backend_decode_join_accept(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *join_accept,
    uint8_t join_accept_len,
    uint8_t *join_accept_clear,
    uint8_t join_format
);

atecc608c_backend_status_t atecc608c_backend_encode_message(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *message,
    uint8_t message_len,
    uint8_t payload_index,
    uint8_t *cipher_out,
    uint8_t key_index
);

atecc608c_backend_status_t atecc608c_backend_verify_mic(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *phy_payload,
    uint8_t phy_len,
    uint32_t devaddr,
    uint32_t fcnt_down,
    uint8_t key_index
);

atecc608c_backend_status_t atecc608c_backend_decode_message(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *phy_payload,
    uint8_t phy_len,
    uint32_t devaddr,
    uint32_t fcnt_down,
    uint8_t key_index,
    uint8_t *clear_out
);

atecc608c_backend_status_t atecc608c_backend_aes128_encrypt(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t key[16],
    const uint8_t input[16],
    uint8_t output[16]
);

#ifdef __cplusplus
}
#endif

#endif // _atecc608c_backend_h_
