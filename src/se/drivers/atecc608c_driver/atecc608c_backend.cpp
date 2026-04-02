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
 * AppKey crypto (join request MIC, join accept decrypt, session key derivation)
 * is performed by the chip's on-board AES-128 engine via atecc608c_aes_ecb_encrypt()
 * using the sealed key in slot 0.  The AppKey never touches host RAM.
 *
 * Session keys (NwkSKey, AppSKey) are derived into RAM after each OTAA join
 * and used with LMIC's software AES for data frame crypto.
 *
 *******************************************************************************/

#include "atecc608c_backend.h"
#include "atecc608c_proto.h"   /* atecc608c_t, atecc608c_aes_ecb_encrypt() */

#include <string.h>

/*
 * Pull in LMIC's AES engine (os_aes, AESkey, AESaux) and helpers.
 * Used for session-key crypto (NwkSKey / AppSKey operations on data frames).
 */
#include "../../../aes/lmic_aes_api.h"
#include "../../../lmic/lmic.h"

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

atecc608c_backend_status_t atecc608c_backend_init(atecc608c_backend_ctx_t *ctx)
{
	if (ctx == NULL) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}

	/* Preserve hardware bindings set by configure() before LMIC_reset(). */
	void *saved_chip        = ctx->chip;
	void *saved_hw_ctx      = ctx->hw_random_ctx;
	bool (*saved_hw_fn)(uint8_t *, uint8_t, void *) = ctx->hw_random;

	memset(ctx, 0, sizeof(*ctx));
	ctx->initialized  = true;
	ctx->chip         = saved_chip;
	ctx->hw_random    = saved_hw_fn;
	ctx->hw_random_ctx = saved_hw_ctx;
	return ATECC608C_BACKEND_STATUS_OK;
}

void atecc608c_backend_set_device(atecc608c_backend_ctx_t *ctx, void *chip_dev)
{
	if (ctx == NULL) {
		return;
	}
	ctx->chip = chip_dev;
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
 *
 * AppKey is sealed on the chip (slot 0).  set_appkey() is a no-op -- the
 * key is already there.  get_appkey() always returns PERMISSION because the
 * key is intentionally unreadable after the data zone is locked.
 *
 * The LMIC framework calls os_getDevKey() → setAppKey() at startup.  The
 * sketch's os_getDevKey() should return dummy zeros; setAppKey() ignores
 * them silently.
 * ========================================================================= */

atecc608c_backend_status_t atecc608c_backend_set_appkey(atecc608c_backend_ctx_t *ctx, const uint8_t key[16])
{
	/* AppKey lives on the chip (slot 0), not in RAM.  Ignore the provided
	 * bytes and return OK so the LMIC startup sequence completes normally. */
	(void)ctx;
	(void)key;
	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_appkey(atecc608c_backend_ctx_t *ctx, uint8_t key[16])
{
	/* AppKey is sealed on chip; reading it back is not permitted. */
	(void)ctx;
	(void)key;
	return ATECC608C_BACKEND_STATUS_PERMISSION;
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
 * Chip AES helpers
 *
 * These use the ATECC608C's on-board AES engine via atecc608c_aes_ecb_encrypt()
 * with the sealed AppKey in slot 0.  Each call manages its own wake/sleep cycle
 * so they can be composed freely without the caller managing chip state.
 * ========================================================================= */

/*
 * chip_ecb -- perform one AES-128-ECB block encryption using slot 0 (AppKey).
 *
 * Wakes the chip, runs the AES command, then sleeps.  in and out may alias.
 * Returns false on I/O error.
 */
static bool chip_ecb(atecc608c_backend_ctx_t *ctx,
                      const uint8_t in[16], uint8_t out[16])
{
	atecc608c_t *dev = (atecc608c_t *)ctx->chip;
	uint8_t wake_resp[4];
	if (!atecc608c_wake(dev, wake_resp)) {
		return false;
	}
	bool ok = atecc608c_aes_ecb_encrypt(dev, 0u, in, out);
	atecc608c_sleep(dev);
	return ok;
}

/*
 * chip_ecb_blocks -- ECB-encrypt each 16-byte block of buf[0..len-1] in place.
 *
 * Used to decrypt the join accept body (AES-128-ECB applied block by block,
 * per LoRaWAN 1.0.x spec -- the "encryption" of the join accept is actually
 * an ECB encrypt operation, which is its own inverse for this usage).
 * len must be a multiple of 16.
 */
static bool chip_ecb_blocks(atecc608c_backend_ctx_t *ctx, uint8_t *buf, int len)
{
	for (int i = 0; i + 16 <= len; i += 16) {
		if (!chip_ecb(ctx, buf + i, buf + i)) {
			return false;
		}
	}
	return true;
}

/*
 * block_shift_left -- shift a 16-byte block left by one bit in-place.
 * Returns the ejected MSB (0 or 1).  Used by chip_aes_cmac().
 */
static uint8_t block_shift_left(uint8_t b[16])
{
	uint8_t msb = (b[0] & 0x80u) ? 1u : 0u;
	for (uint8_t i = 0u; i < 15u; ++i) {
		b[i] = (uint8_t)((b[i] << 1) | (b[i + 1] >> 7));
	}
	b[15] = (uint8_t)(b[15] << 1);
	return msb;
}

/*
 * chip_aes_cmac -- AES-128-CMAC (RFC 4493) using chip slot 0 (AppKey).
 *
 * Computes the full 16-byte CMAC of msg[0..len-1] and stores it in mac[0..15].
 * Uses (n+1) chip AES-ECB calls where n = ceil(len/16).
 *
 * Returns false on chip I/O error.
 */
static bool chip_aes_cmac(atecc608c_backend_ctx_t *ctx,
                           const uint8_t *msg, int len, uint8_t mac[16])
{
	uint8_t K1[16], K2[16], X[16], tmp[16];

	/* Step 1: derive subkeys K1, K2 from AES(AppKey, 0^16) */
	memset(tmp, 0, 16);
	if (!chip_ecb(ctx, tmp, K1)) {
		return false;
	}

	if (block_shift_left(K1)) { /* MSB was 1 → XOR with Rb = 0^15 || 0x87 */
		K1[15] ^= 0x87u;
	}
	memcpy(K2, K1, 16);
	if (block_shift_left(K2)) {
		K2[15] ^= 0x87u;
	}

	/* Step 2: process all but the last block */
	int n = (len + 15) / 16;
	if (n == 0) {
		n = 1; /* treat empty message as one padded block */
	}

	bool complete = (len > 0) && ((len % 16) == 0);

	memset(X, 0, 16);
	for (int i = 0; i < n - 1; ++i) {
		for (uint8_t j = 0u; j < 16u; ++j) {
			X[j] ^= msg[i * 16 + j];
		}
		if (!chip_ecb(ctx, X, X)) {
			return false;
		}
	}

	/* Step 3: process last block (with padding if incomplete) */
	memset(tmp, 0, 16);
	int tail = complete ? 16 : (len % 16);
	if (len > 0) {
		memcpy(tmp, msg + (n - 1) * 16, tail);
	}
	if (!complete) {
		tmp[tail] = 0x80u; /* ISO/IEC 9797-1 padding */
	}

	const uint8_t *K = complete ? K1 : K2;
	for (uint8_t j = 0u; j < 16u; ++j) {
		tmp[j] ^= X[j] ^ K[j];
	}

	return chip_ecb(ctx, tmp, mac);
}

/* =========================================================================
 * Internal software AES helpers (session key operations -- NwkSKey/AppSKey
 * remain in RAM; chip AES is only used for AppKey operations above).
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

/*
 * Append MIC using AppKey (AES-CMAC via chip, no auxiliary B0 block).
 * Returns false on chip I/O error.
 */
static bool backend_appendMic0(atecc608c_backend_ctx_t *ctx, uint8_t *pdu, int len)
{
	uint8_t mac[16];
	if (!chip_aes_cmac(ctx, pdu, len, mac)) {
		return false;
	}
	/* Store the first 4 bytes of the MAC, MSB first */
	pdu[len + 0] = mac[0];
	pdu[len + 1] = mac[1];
	pdu[len + 2] = mac[2];
	pdu[len + 3] = mac[3];
	return true;
}

/*
 * Verify MIC using AppKey (AES-CMAC via chip, no auxiliary B0 block).
 * Returns 1 if MIC matches, 0 if mismatch, -1 on chip I/O error.
 */
static int backend_verifyMic0(atecc608c_backend_ctx_t *ctx, const uint8_t *pdu, int len)
{
	uint8_t mac[16];
	if (!chip_aes_cmac(ctx, pdu, len, mac)) {
		return -1;
	}
	/* Compare first 4 bytes of computed MAC against stored MIC (MSB first) */
	return (mac[0] == pdu[len + 0] &&
	        mac[1] == pdu[len + 1] &&
	        mac[2] == pdu[len + 2] &&
	        mac[3] == pdu[len + 3]) ? 1 : 0;
}

/*
 * Derive NwkSKey and AppSKey from join-accept fields using chip AES.
 * Stores results into ctx->nwkskey[0] and ctx->appskey[0] (RAM).
 * Returns false on chip I/O error.
 */
static bool backend_sessKeys(atecc608c_backend_ctx_t *ctx, u2_t devnonce,
                              const uint8_t *artnonce)
{
	uint8_t *nwkkey = ctx->nwkskey[0];
	uint8_t *artkey = ctx->appskey[0];

	/* Build derivation templates:
	 *   NwkSKey = AES128(AppKey, 0x01 || AppNonce || NetID || DevNonce || pad)
	 *   AppSKey = AES128(AppKey, 0x02 || AppNonce || NetID || DevNonce || pad)
	 */
	os_clearMem(nwkkey, 16);
	nwkkey[0] = 0x01;
	os_copyMem(nwkkey + 1, artnonce, LEN_ARTNONCE + LEN_NETID);
	os_wlsbf2(nwkkey + 1 + LEN_ARTNONCE + LEN_NETID, devnonce);
	os_copyMem(artkey, nwkkey, 16);
	artkey[0] = 0x02;

	/* Encrypt each template with AppKey via chip */
	if (!chip_ecb(ctx, nwkkey, nwkkey)) {
		return false;
	}
	if (!chip_ecb(ctx, artkey, artkey)) {
		return false;
	}

	ctx->nwkskey_present[0] = true;
	ctx->appskey_present[0] = true;
	return true;
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
	if (ctx->chip == NULL) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED; /* chip not wired */
	}
	if (!ctx->appeui_present || !ctx->deveui_present) {
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

	if (!backend_appendMic0(ctx, d, OFF_JR_MIC)) {
		return ATECC608C_BACKEND_STATUS_IO_ERROR;
	}

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
	if (ctx->chip == NULL) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	if (join_format != LMIC_SecureElement_JoinFormat_JoinRequest10) {
		return ATECC608C_BACKEND_STATUS_UNSUPPORTED;
	}

	if (join_accept_clear != join_accept) {
		os_copyMem(join_accept_clear, join_accept, join_accept_len);
	}

	/* Decrypt join accept body (AES-128-ECB, applied block-by-block from byte 1) */
	if (!chip_ecb_blocks(ctx, join_accept_clear + 1, join_accept_len - 1)) {
		return ATECC608C_BACKEND_STATUS_IO_ERROR;
	}

	/* Verify MIC */
	int mic_ok = backend_verifyMic0(ctx, join_accept_clear, join_accept_len - 4);
	if (mic_ok < 0) {
		return ATECC608C_BACKEND_STATUS_IO_ERROR;
	}
	if (mic_ok == 0) {
		return ATECC608C_BACKEND_STATUS_CRYPTO_ERROR;
	}

	/* Derive and store session keys */
	if (!backend_sessKeys(ctx, LMIC.devNonce - 1,
	                      &join_accept_clear[OFF_JA_ARTNONCE])) {
		return ATECC608C_BACKEND_STATUS_IO_ERROR;
	}

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
	if (key_index != 0u || message_len < 9u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->nwkskey_present[0] || !ctx->appskey_present[0]) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}

	if (cipher_out != message) {
		os_copyMem(cipher_out, message, message_len);
	}

	const uint8_t nData = message_len - 4u;

	if ((uint8_t)(payload_index + 1u) < nData) {
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

	uint8_t nPayload = phy_len - 4u;

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
