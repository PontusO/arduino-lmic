#include "atecc608c_backend.h"

#include <string.h>

/*
 * Development stub backend.
 *
 * Replace this file later with a real ATECC608C implementation.
 */

#define ATECC608C_BACKEND_ALLOW_APPKEY_READBACK 0

atecc608c_backend_status_t atecc608c_backend_init(atecc608c_backend_ctx_t *ctx)
{
    if (ctx == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->initialized = true;
    ctx->appkey_readable = ATECC608C_BACKEND_ALLOW_APPKEY_READBACK ? true : false;
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_random(atecc608c_backend_ctx_t *ctx, uint8_t *buf, uint8_t len)
{
    static uint32_t x = 0x6D2B79F5u;

    if (ctx == NULL || buf == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }

    for (uint8_t i = 0; i < len; ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)x;
    }

    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_set_appkey(atecc608c_backend_ctx_t *ctx, const uint8_t key[16])
{
    if (ctx == NULL || key == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }

    memcpy(ctx->appkey, key, 16);
    ctx->appkey_present = true;
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_appkey(atecc608c_backend_ctx_t *ctx, uint8_t key[16])
{
    if (ctx == NULL || key == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }
    if (!ctx->appkey_present) {
        return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
    }
    if (!ctx->appkey_readable) {
        return ATECC608C_BACKEND_STATUS_PERMISSION;
    }

    memcpy(key, ctx->appkey, 16);
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_set_appeui(atecc608c_backend_ctx_t *ctx, const uint8_t eui[8])
{
    if (ctx == NULL || eui == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }

    memcpy(ctx->appeui, eui, 8);
    ctx->appeui_present = true;
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_appeui(atecc608c_backend_ctx_t *ctx, uint8_t eui[8])
{
    if (ctx == NULL || eui == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }
    if (!ctx->appeui_present) {
        return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
    }

    memcpy(eui, ctx->appeui, 8);
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_set_deveui(atecc608c_backend_ctx_t *ctx, const uint8_t eui[8])
{
    if (ctx == NULL || eui == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }

    memcpy(ctx->deveui, eui, 8);
    ctx->deveui_present = true;
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_deveui(atecc608c_backend_ctx_t *ctx, uint8_t eui[8])
{
    if (ctx == NULL || eui == NULL) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }
    if (!ctx->deveui_present) {
        return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
    }

    memcpy(eui, ctx->deveui, 8);
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_set_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16])
{
    if (ctx == NULL || key == NULL || key_index >= 5) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }

    memcpy(ctx->nwkskey[key_index], key, 16);
    ctx->nwkskey_present[key_index] = true;
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16])
{
    if (ctx == NULL || key == NULL || key_index >= 5) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }
    if (!ctx->nwkskey_present[key_index]) {
        return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
    }

    memcpy(key, ctx->nwkskey[key_index], 16);
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_set_appskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16])
{
    if (ctx == NULL || key == NULL || key_index >= 5) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }

    memcpy(ctx->appskey[key_index], key, 16);
    ctx->appskey_present[key_index] = true;
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_appskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16])
{
    if (ctx == NULL || key == NULL || key_index >= 5) {
        return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
    }
    if (!ctx->initialized) {
        return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
    }
    if (!ctx->appskey_present[key_index]) {
        return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
    }

    memcpy(key, ctx->appskey[key_index], 16);
    return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_create_join_request(
    atecc608c_backend_ctx_t *ctx,
    uint8_t join_request[23],
    uint8_t join_format)
{
    (void)ctx;
    (void)join_request;
    (void)join_format;
    return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
}

atecc608c_backend_status_t atecc608c_backend_decode_join_accept(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *join_accept,
    uint8_t join_accept_len,
    uint8_t *join_accept_clear,
    uint8_t join_format)
{
    (void)ctx;
    (void)join_accept;
    (void)join_accept_len;
    (void)join_accept_clear;
    (void)join_format;
    return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
}

atecc608c_backend_status_t atecc608c_backend_encode_message(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *message,
    uint8_t message_len,
    uint8_t payload_index,
    uint8_t *cipher_out,
    uint8_t key_index)
{
    (void)ctx;
    (void)message;
    (void)message_len;
    (void)payload_index;
    (void)cipher_out;
    (void)key_index;
    return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
}

atecc608c_backend_status_t atecc608c_backend_verify_mic(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *phy_payload,
    uint8_t phy_len,
    uint32_t devaddr,
    uint32_t fcnt_down,
    uint8_t key_index)
{
    (void)ctx;
    (void)phy_payload;
    (void)phy_len;
    (void)devaddr;
    (void)fcnt_down;
    (void)key_index;
    return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
}

atecc608c_backend_status_t atecc608c_backend_decode_message(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t *phy_payload,
    uint8_t phy_len,
    uint32_t devaddr,
    uint32_t fcnt_down,
    uint8_t key_index,
    uint8_t *clear_out)
{
    (void)ctx;
    (void)phy_payload;
    (void)phy_len;
    (void)devaddr;
    (void)fcnt_down;
    (void)key_index;
    (void)clear_out;
    return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
}

atecc608c_backend_status_t atecc608c_backend_aes128_encrypt(
    atecc608c_backend_ctx_t *ctx,
    const uint8_t key[16],
    const uint8_t input[16],
    uint8_t output[16])
{
    (void)ctx;
    (void)key;
    (void)input;
    (void)output;
    return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
}
