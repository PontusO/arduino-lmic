#ifndef _stsafe_a120_backend_h_
#define _stsafe_a120_backend_h_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum stsafe_a120_backend_status_e {
    STSAFE_A120_BACKEND_STATUS_OK = 0,
    STSAFE_A120_BACKEND_STATUS_INVALID_PARAM,
    STSAFE_A120_BACKEND_STATUS_NOT_INITIALIZED,
    STSAFE_A120_BACKEND_STATUS_NOT_PROVISIONED,
    STSAFE_A120_BACKEND_STATUS_PERMISSION,
    STSAFE_A120_BACKEND_STATUS_UNSUPPORTED,
    STSAFE_A120_BACKEND_STATUS_IO_ERROR,
    STSAFE_A120_BACKEND_STATUS_CRYPTO_ERROR,
} stsafe_a120_backend_status_t;

typedef struct stsafe_a120_backend_ctx_s {
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
} stsafe_a120_backend_ctx_t;

/* lifecycle */
stsafe_a120_backend_status_t stsafe_a120_backend_init(stsafe_a120_backend_ctx_t *ctx);

/* randomness */
stsafe_a120_backend_status_t stsafe_a120_backend_random(stsafe_a120_backend_ctx_t *ctx, uint8_t *buf, uint8_t len);

/* root credentials */
stsafe_a120_backend_status_t stsafe_a120_backend_set_appkey(stsafe_a120_backend_ctx_t *ctx, const uint8_t key[16]);
stsafe_a120_backend_status_t stsafe_a120_backend_get_appkey(stsafe_a120_backend_ctx_t *ctx, uint8_t key[16]);

stsafe_a120_backend_status_t stsafe_a120_backend_set_appeui(stsafe_a120_backend_ctx_t *ctx, const uint8_t eui[8]);
stsafe_a120_backend_status_t stsafe_a120_backend_get_appeui(stsafe_a120_backend_ctx_t *ctx, uint8_t eui[8]);

stsafe_a120_backend_status_t stsafe_a120_backend_set_deveui(stsafe_a120_backend_ctx_t *ctx, const uint8_t eui[8]);
stsafe_a120_backend_status_t stsafe_a120_backend_get_deveui(stsafe_a120_backend_ctx_t *ctx, uint8_t eui[8]);

/* session credentials */
stsafe_a120_backend_status_t stsafe_a120_backend_set_nwkskey(stsafe_a120_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16]);
stsafe_a120_backend_status_t stsafe_a120_backend_get_nwkskey(stsafe_a120_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16]);

stsafe_a120_backend_status_t stsafe_a120_backend_set_appskey(stsafe_a120_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16]);
stsafe_a120_backend_status_t stsafe_a120_backend_get_appskey(stsafe_a120_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16]);

/* crypto hooks - stub now, real later */
stsafe_a120_backend_status_t stsafe_a120_backend_create_join_request(
    stsafe_a120_backend_ctx_t *ctx,
    uint8_t join_request[23],
    uint8_t join_format
);

stsafe_a120_backend_status_t stsafe_a120_backend_decode_join_accept(
    stsafe_a120_backend_ctx_t *ctx,
    const uint8_t *join_accept,
    uint8_t join_accept_len,
    uint8_t *join_accept_clear,
    uint8_t join_format
);

stsafe_a120_backend_status_t stsafe_a120_backend_encode_message(
    stsafe_a120_backend_ctx_t *ctx,
    const uint8_t *message,
    uint8_t message_len,
    uint8_t payload_index,
    uint8_t *cipher_out,
    uint8_t key_index
);

stsafe_a120_backend_status_t stsafe_a120_backend_verify_mic(
    stsafe_a120_backend_ctx_t *ctx,
    const uint8_t *phy_payload,
    uint8_t phy_len,
    uint32_t devaddr,
    uint32_t fcnt_down,
    uint8_t key_index
);

stsafe_a120_backend_status_t stsafe_a120_backend_decode_message(
    stsafe_a120_backend_ctx_t *ctx,
    const uint8_t *phy_payload,
    uint8_t phy_len,
    uint32_t devaddr,
    uint32_t fcnt_down,
    uint8_t key_index,
    uint8_t *clear_out
);

stsafe_a120_backend_status_t stsafe_a120_backend_aes128_encrypt(
    stsafe_a120_backend_ctx_t *ctx,
    const uint8_t key[16],
    const uint8_t input[16],
    uint8_t output[16]
);

#ifdef __cplusplus
}
#endif

#endif // _stsafe_a120_backend_h_
