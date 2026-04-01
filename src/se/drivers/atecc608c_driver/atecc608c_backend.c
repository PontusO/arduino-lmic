/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C crypto backend (implementation).
 *
 *******************************************************************************/

#include "atecc608c_backend.h"

#include <string.h>

/*
 * Pull in LMIC's AES engine (os_aes, AESkey, AESaux) and the LMIC global
 * struct (LMIC.devaddr, LMIC.seqnoUp, LMIC.devNonce), frame-format constants
 * (OFF_JR_*, OFF_JA_*, OFF_DAT_*, HDR_FTYPE_JREQ, LEN_ARTNONCE, LEN_NETID, …)
 * and helpers (os_copyMem, os_clearMem, os_wlsbf2/4, os_wmsbf4, os_rmsbf4).
 * This mirrors the approach used by lmic_se_default.c.
 */
#include "../../../aes/lmic_aes_api.h"
#include "../../../lmic/lmic.h"

#define ATECC608C_BACKEND_ALLOW_APPKEY_READBACK 0

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

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

void atecc608c_backend_set_hw_random(atecc608c_backend_ctx_t *ctx,
                                      bool (*fn)(uint8_t *out, uint8_t len, void *user_ctx),
                                      void *user_ctx)
{
	if (ctx == NULL) {
		return;
	}
	ctx->hw_random     = fn;
	ctx->hw_random_ctx = user_ctx;
}

/* =========================================================================
 * Randomness
 * ========================================================================= */

atecc608c_backend_status_t atecc608c_backend_random(atecc608c_backend_ctx_t *ctx, uint8_t *buf, uint8_t len)
{
	if (ctx == NULL || buf == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}

	if (ctx->hw_random != NULL) {
		/*
		 * Hardware RNG: call in chunks of at most 32 bytes (one ATECC608C
		 * Random command returns 32 bytes).
		 */
		uint8_t remaining = len;
		uint8_t offset    = 0;
		while (remaining > 0u) {
			uint8_t chunk = (remaining > 32u) ? 32u : remaining;
			if (!ctx->hw_random(buf + offset, chunk, ctx->hw_random_ctx)) {
				return ATECC608C_BACKEND_STATUS_IO_ERROR;
			}
			offset    += chunk;
			remaining -= chunk;
		}
		return ATECC608C_BACKEND_STATUS_OK;
	}

	/* Software fallback: xorshift32 PRNG */
	static uint32_t x = 0x6D2B79F5u;
	for (uint8_t i = 0; i < len; ++i) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		buf[i] = (uint8_t)x;
	}
	return ATECC608C_BACKEND_STATUS_OK;
}

/* =========================================================================
 * Root credential setters / getters
 * ========================================================================= */

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

/* =========================================================================
 * Session credential setters / getters
 * ========================================================================= */

atecc608c_backend_status_t atecc608c_backend_set_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16])
{
	if (ctx == NULL || key == NULL || key_index >= 5u) {
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
	if (ctx == NULL || key == NULL || key_index >= 5u) {
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
	if (ctx == NULL || key == NULL || key_index >= 5u) {
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
	if (ctx == NULL || key == NULL || key_index >= 5u) {
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

/* =========================================================================
 * Internal AES helpers -- mirror lmic_se_default.c exactly, using keys from
 * the backend context instead of the default SE's static variables.
 * ========================================================================= */

static void backend_micB0(u4_t devaddr, u4_t seqno, int dndir, int len)
{
	os_clearMem(AESaux, 16);
	AESaux[0]  = 0x49;
	AESaux[5]  = dndir ? 1 : 0;
	AESaux[15] = len;
	os_wlsbf4(AESaux + 6,  devaddr);
	os_wlsbf4(AESaux + 10, seqno);
}

static int backend_verifyMic(const uint8_t *key, u4_t devaddr, u4_t seqno,
                              int dndir, const uint8_t *pdu, int len)
{
	backend_micB0(devaddr, seqno, dndir, len);
	os_copyMem(AESkey, key, 16);
	return os_aes(AES_MIC, /* deconst */(u1_t *)pdu, len) == os_rmsbf4(pdu + len);
}

static void backend_appendMic(const uint8_t *key, u4_t devaddr, u4_t seqno,
                               int dndir, uint8_t *pdu, int len)
{
	backend_micB0(devaddr, seqno, dndir, len);
	os_copyMem(AESkey, key, 16);
	os_wmsbf4(pdu + len, os_aes(AES_MIC, pdu, len));
}

static void backend_cipher(const uint8_t *key, u4_t devaddr, u4_t seqno,
                            int dndir, uint8_t *payload, int len)
{
	if (len <= 0) {
		return;
	}
	os_clearMem(AESaux, 16);
	AESaux[0] = AESaux[15] = 1;
	AESaux[5] = dndir ? 1 : 0;
	os_wlsbf4(AESaux + 6,  devaddr);
	os_wlsbf4(AESaux + 10, seqno);
	os_copyMem(AESkey, key, 16);
	os_aes(AES_CTR, payload, len);
}

/* AES-ECB encrypt using AppKey */
static void backend_ecb_appkey(atecc608c_backend_ctx_t *ctx, uint8_t *block, int len)
{
	os_copyMem(AESkey, ctx->appkey, 16);
	os_aes(AES_ENC, block, len);
}

/* Append MIC using AppKey (AES-CMAC, no auxiliary block) */
static void backend_appendMic0(atecc608c_backend_ctx_t *ctx, uint8_t *pdu, int len)
{
	os_copyMem(AESkey, ctx->appkey, 16);
	os_wmsbf4(pdu + len, os_aes(AES_MIC | AES_MICNOAUX, pdu, len));
}

static int backend_verifyMic0(atecc608c_backend_ctx_t *ctx, uint8_t *pdu, int len)
{
	os_copyMem(AESkey, ctx->appkey, 16);
	return os_aes(AES_MIC | AES_MICNOAUX, pdu, len) == os_rmsbf4(pdu + len);
}

/* Derive NwkSKey and AppSKey from join-accept fields, store in ctx->nwkskey[0]/appskey[0]. */
static void backend_sessKeys(atecc608c_backend_ctx_t *ctx, u2_t devnonce,
                              const uint8_t *artnonce)
{
	uint8_t *nwkkey = ctx->nwkskey[0];
	uint8_t *artkey = ctx->appskey[0];

	os_clearMem(nwkkey, 16);
	nwkkey[0] = 0x01;
	os_copyMem(nwkkey + 1, artnonce, LEN_ARTNONCE + LEN_NETID);
	os_wlsbf2(nwkkey + 1 + LEN_ARTNONCE + LEN_NETID, devnonce);
	os_copyMem(artkey, nwkkey, 16);
	artkey[0] = 0x02;

	backend_ecb_appkey(ctx, nwkkey, 16);
	backend_ecb_appkey(ctx, artkey, 16);

	ctx->nwkskey_present[0] = true;
	ctx->appskey_present[0] = true;
}

/* =========================================================================
 * Crypto hooks
 * ========================================================================= */

atecc608c_backend_status_t atecc608c_backend_create_join_request(
	atecc608c_backend_ctx_t *ctx,
	uint8_t join_request[23],
	uint8_t join_format)
{
	if (ctx == NULL || join_request == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	if (!ctx->appkey_present || !ctx->appeui_present || !ctx->deveui_present) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}
	if (join_format != LMIC_SecureElement_JoinFormat_JoinRequest10) {
		return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
	}

	uint8_t *d = join_request;
	d[OFF_JR_HDR] = HDR_FTYPE_JREQ;
	memcpy(d + OFF_JR_ARTEUI,   ctx->appeui, 8);
	memcpy(d + OFF_JR_DEVEUI,   ctx->deveui, 8);
	os_wlsbf2(d + OFF_JR_DEVNONCE, LMIC.devNonce);
	backend_appendMic0(ctx, d, OFF_JR_MIC);

	LMIC.devNonce++;
	DO_DEVDB(LMIC.devNonce, devNonce);
	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_decode_join_accept(
	atecc608c_backend_ctx_t *ctx,
	const uint8_t *join_accept,
	uint8_t join_accept_len,
	uint8_t *join_accept_clear,
	uint8_t join_format)
{
	if (ctx == NULL || join_accept == NULL || join_accept_clear == NULL ||
	    join_accept_len == 0u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	if (!ctx->appkey_present) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}
	if (join_format != LMIC_SecureElement_JoinFormat_JoinRequest10) {
		return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
	}

	if (join_accept_clear != join_accept) {
		os_copyMem(join_accept_clear, join_accept, join_accept_len);
	}

	/* Decrypt the join accept (AES-ECB, applied to bytes 1..) */
	backend_ecb_appkey(ctx, join_accept_clear + 1, join_accept_len - 1);

	/* Verify MIC */
	if (!backend_verifyMic0(ctx, join_accept_clear, join_accept_len - 4)) {
		return ATECC608C_BACKEND_STATUS_CRYPTO_ERROR;
	}

	/* Derive and store session keys */
	backend_sessKeys(ctx, LMIC.devNonce - 1,
	                 &join_accept_clear[OFF_JA_ARTNONCE]);

	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_encode_message(
	atecc608c_backend_ctx_t *ctx,
	const uint8_t *message,
	uint8_t message_len,
	uint8_t payload_index,
	uint8_t *cipher_out,
	uint8_t key_index)
{
	if (ctx == NULL || message == NULL || cipher_out == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	/*
	 * Only Unicast is supported for uplink encode, matching the default SE.
	 * message_len includes the 4 MIC bytes (not yet computed); minimum frame
	 * is MHDR + 4-byte FHDR + 4-byte MIC = 9 bytes.
	 */
	if (key_index != 0u || message_len < 9u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->nwkskey_present[0] || !ctx->appskey_present[0]) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}

	if (cipher_out != message) {
		os_copyMem(cipher_out, message, message_len);
	}

	const uint8_t nData = message_len - 4u; /* frame length without MIC */

	if ((uint8_t)(payload_index + 1u) < nData) {
		/*
		 * Non-empty payload: select AppSKey (port != 0) or NwkSKey (port == 0).
		 */
		const uint8_t *enc_key =
			(cipher_out[payload_index] == 0u) ? ctx->nwkskey[0] : ctx->appskey[0];
		backend_cipher(
			enc_key,
			LMIC.devaddr,
			LMIC.seqnoUp - 1u,
			/* uplink */ 0,
			cipher_out + payload_index + 1u,
			nData - payload_index - 1u);
	}

	backend_appendMic(
		ctx->nwkskey[0],
		LMIC.devaddr,
		LMIC.seqnoUp - 1u,
		/* uplink */ 0,
		cipher_out,
		nData);

	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_verify_mic(
	atecc608c_backend_ctx_t *ctx,
	const uint8_t *phy_payload,
	uint8_t phy_len,
	uint32_t devaddr,
	uint32_t fcnt_down,
	uint8_t key_index)
{
	if (ctx == NULL || phy_payload == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	if (key_index >= 5u || phy_len < 4u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->nwkskey_present[key_index]) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}

	if (!backend_verifyMic(
			ctx->nwkskey[key_index],
			devaddr, fcnt_down, /* downlink */ 1,
			phy_payload, phy_len - 4u)) {
		return ATECC608C_BACKEND_STATUS_CRYPTO_ERROR;
	}
	return ATECC608C_BACKEND_STATUS_OK;
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
	if (ctx == NULL || phy_payload == NULL || clear_out == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	if (key_index >= 5u || phy_len < 4u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->nwkskey_present[key_index] || !ctx->appskey_present[key_index]) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}

	uint8_t nPayload = phy_len - 4u; /* strip MIC */

	if (clear_out != phy_payload) {
		os_copyMem(clear_out, phy_payload, nPayload);
	}

	uint8_t FOptsLen   = clear_out[OFF_DAT_FCT] & FCT_OPTLEN;
	uint8_t portOffset = OFF_DAT_OPTS + FOptsLen;
	int     port       = 0;

	if (portOffset < nPayload) {
		port = clear_out[portOffset];
		++portOffset;
	}

	if (portOffset < nPayload) {
		const uint8_t *dec_key =
			(port != 0) ? ctx->appskey[key_index] : ctx->nwkskey[key_index];
		backend_cipher(
			dec_key,
			devaddr,
			fcnt_down,
			/* downlink */ 1,
			clear_out + portOffset,
			nPayload - portOffset);
	}

	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_aes128_encrypt(
	atecc608c_backend_ctx_t *ctx,
	const uint8_t key[16],
	const uint8_t input[16],
	uint8_t output[16])
{
	if (ctx == NULL || key == NULL || input == NULL || output == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}

	if (output != input) {
		os_copyMem(output, input, 16);
	}
	os_copyMem(AESkey, key, 16);
	os_aes(AES_ENC, output, 16);
	return ATECC608C_BACKEND_STATUS_OK;
}
