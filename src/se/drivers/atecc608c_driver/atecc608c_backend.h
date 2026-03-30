#ifndef _atecc608c_backend_h_
#define _atecc608c_backend_h_

#include <stdint.h>
#include <stdbool.h>

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
} atecc608c_backend_ctx_t;

/* lifecycle */
atecc608c_backend_status_t atecc608c_backend_init(atecc608c_backend_ctx_t *ctx);

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
