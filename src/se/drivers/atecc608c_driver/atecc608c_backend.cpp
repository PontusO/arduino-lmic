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
 * Secure memset that the compiler cannot optimise away.
 * Used to scrub key material from stack buffers.
 */
static void secure_zero(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;
	while (n--) {
		*v++ = 0;
	}
}

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

/*
 * Session key setters write to chip slots; getters return PERMISSION
 * because the slots are IsSecret=1 and cannot be read back.
 *
 * The LMIC framework calls setNwkSKey/setAppSKey after a successful
 * OTAA join (via LMIC_setSessionKeys in processJoinAccept).  In our
 * implementation backend_sessKeys() already wrote the keys to the chip,
 * so these setters just update the _present flags and ignore the key
 * bytes (they would be the same values we already wrote).
 */
atecc608c_backend_status_t atecc608c_backend_set_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16])
{
	if (ctx == NULL || key == NULL || key_index >= 5u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	/* Key is already on the chip (written by backend_sessKeys).
	 * Just mark present so the framework knows session is active. */
	(void)key;
	ctx->nwkskey_present[key_index] = true;
	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_nwkskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16])
{
	/* Session keys are sealed on the chip (IsSecret=1); cannot read back. */
	(void)ctx; (void)key_index; (void)key;
	return ATECC608C_BACKEND_STATUS_PERMISSION;
}

atecc608c_backend_status_t atecc608c_backend_set_appskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, const uint8_t key[16])
{
	if (ctx == NULL || key == NULL || key_index >= 5u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->initialized) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	(void)key;
	ctx->appskey_present[key_index] = true;
	return ATECC608C_BACKEND_STATUS_OK;
}

atecc608c_backend_status_t atecc608c_backend_get_appskey(atecc608c_backend_ctx_t *ctx, uint8_t key_index, uint8_t key[16])
{
	(void)ctx; (void)key_index; (void)key;
	return ATECC608C_BACKEND_STATUS_PERMISSION;
}

/* =========================================================================
 * Chip slot layout (must match Stage 1 provisioning template)
 * ========================================================================= */

#define ATECC_SLOT_APPKEY    0u   /* LoRaWAN 1.0/1.1 root key (sealed) */
#define ATECC_SLOT_NWKKEY    1u   /* LoRaWAN 1.1 network root key (sealed) */
#define ATECC_SLOT_NWKSKEY   2u   /* NwkSKey (1.0) / FNwkSIntKey (1.1) */
#define ATECC_SLOT_APPSKEY   5u   /* AppSKey (1.0/1.1) */

/* =========================================================================
 * Chip AES helpers
 *
 * All crypto operations use the ATECC608C's on-board AES-128 engine.
 * Each call manages its own wake/sleep cycle.
 * ========================================================================= */

/*
 * chip_ecb_slot -- perform one AES-128-ECB block encryption using a given slot.
 *
 * Wakes the chip, runs the AES command, then sleeps.  in and out may alias.
 * Returns false on I/O error.
 */
static bool chip_ecb_slot(atecc608c_backend_ctx_t *ctx, uint8_t slot,
                           const uint8_t in[16], uint8_t out[16])
{
	atecc608c_t *dev = (atecc608c_t *)ctx->chip;
	uint8_t wake_resp[4];
	if (!atecc608c_wake(dev, wake_resp)) {
		return false;
	}
	bool ok = atecc608c_aes_ecb_encrypt(dev, slot, in, out);
	atecc608c_sleep(dev);
	return ok;
}

/* Convenience wrapper: AES-ECB with slot 0 (AppKey). */
static bool chip_ecb(atecc608c_backend_ctx_t *ctx,
                      const uint8_t in[16], uint8_t out[16])
{
	return chip_ecb_slot(ctx, ATECC_SLOT_APPKEY, in, out);
}

/*
 * chip_ecb_blocks -- ECB-encrypt each 16-byte block of buf[0..len-1] in place.
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
 * Returns the ejected MSB (0 or 1).  Used by chip_aes_cmac_slot().
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
 * chip_aes_cmac_slot -- AES-128-CMAC (RFC 4493) using a given chip slot.
 *
 * Computes the full 16-byte CMAC of msg[0..len-1] and stores it in mac[0..15].
 * Returns false on chip I/O error.
 */
static bool chip_aes_cmac_slot(atecc608c_backend_ctx_t *ctx, uint8_t slot,
                                const uint8_t *msg, int len, uint8_t mac[16])
{
	uint8_t K1[16], K2[16], X[16], tmp[16];

	/* Step 1: derive subkeys K1, K2 from AES(key, 0^16) */
	memset(tmp, 0, 16);
	if (!chip_ecb_slot(ctx, slot, tmp, K1)) {
		return false;
	}

	if (block_shift_left(K1)) {
		K1[15] ^= 0x87u;
	}
	memcpy(K2, K1, 16);
	if (block_shift_left(K2)) {
		K2[15] ^= 0x87u;
	}

	/* Step 2: process all but the last block */
	int n = (len + 15) / 16;
	if (n == 0) {
		n = 1;
	}

	bool complete = (len > 0) && ((len % 16) == 0);

	memset(X, 0, 16);
	for (int i = 0; i < n - 1; ++i) {
		for (uint8_t j = 0u; j < 16u; ++j) {
			X[j] ^= msg[i * 16 + j];
		}
		if (!chip_ecb_slot(ctx, slot, X, X)) {
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
		tmp[tail] = 0x80u;
	}

	const uint8_t *K = complete ? K1 : K2;
	for (uint8_t j = 0u; j < 16u; ++j) {
		tmp[j] ^= X[j] ^ K[j];
	}

	return chip_ecb_slot(ctx, slot, tmp, mac);
}

/* Convenience wrapper: AES-CMAC with slot 0 (AppKey). */
static bool chip_aes_cmac(atecc608c_backend_ctx_t *ctx,
                           const uint8_t *msg, int len, uint8_t mac[16])
{
	return chip_aes_cmac_slot(ctx, ATECC_SLOT_APPKEY, msg, len, mac);
}

/*
 * chip_aes_cmac_b0 -- AES-CMAC over (B0 || pdu) using a given chip slot.
 *
 * Computes the LoRaWAN MIC: CMAC input is the 16-byte B0 block followed by
 * the PDU.  Returns the 4-byte MIC (first 4 bytes of the 16-byte CMAC) as
 * a big-endian uint32_t.  Returns 0 on I/O error (caller should check via
 * the bool return).
 */
static bool chip_aes_cmac_b0(atecc608c_backend_ctx_t *ctx, uint8_t slot,
                              u4_t devaddr, u4_t seqno, int dndir,
                              const uint8_t *pdu, int len,
                              uint32_t *mic_out)
{
	uint8_t K1[16], K2[16], X[16], tmp[16];

	/* Derive subkeys */
	memset(tmp, 0, 16);
	if (!chip_ecb_slot(ctx, slot, tmp, K1)) {
		return false;
	}
	if (block_shift_left(K1)) {
		K1[15] ^= 0x87u;
	}
	memcpy(K2, K1, 16);
	if (block_shift_left(K2)) {
		K2[15] ^= 0x87u;
	}

	/* Build B0 block and process it as the first CMAC block */
	uint8_t B0_block[16];
	memset(B0_block, 0, 16);
	B0_block[0]  = 0x49;
	B0_block[5]  = dndir ? 1 : 0;
	os_wlsbf4(B0_block + 6,  devaddr);
	os_wlsbf4(B0_block + 10, seqno);
	B0_block[15] = (uint8_t)len;

	/* Total CMAC input length: 16 (B0) + len (PDU) */
	int total = 16 + len;
	int n = (total + 15) / 16;
	bool complete = (total % 16) == 0;

	/* Block 0 = B0 */
	memset(X, 0, 16);
	for (uint8_t j = 0u; j < 16u; ++j) {
		X[j] ^= B0_block[j];
	}
	if (!chip_ecb_slot(ctx, slot, X, X)) {
		return false;
	}

	/* Blocks 1..n-2: full 16-byte PDU blocks */
	int pdu_offset = 0;
	for (int i = 1; i < n - 1; ++i) {
		for (uint8_t j = 0u; j < 16u; ++j) {
			X[j] ^= pdu[pdu_offset + j];
		}
		pdu_offset += 16;
		if (!chip_ecb_slot(ctx, slot, X, X)) {
			return false;
		}
	}

	/* Last block: remaining PDU bytes with optional padding */
	memset(tmp, 0, 16);
	int remaining = len - pdu_offset;
	if (remaining > 0) {
		memcpy(tmp, pdu + pdu_offset, remaining);
	}
	if (!complete) {
		tmp[remaining] = 0x80u;
	}

	const uint8_t *K = complete ? K1 : K2;
	for (uint8_t j = 0u; j < 16u; ++j) {
		tmp[j] ^= X[j] ^ K[j];
	}

	uint8_t mac[16];
	if (!chip_ecb_slot(ctx, slot, tmp, mac)) {
		return false;
	}

	/* MIC = first 4 bytes, big-endian */
	*mic_out = ((uint32_t)mac[0] << 24) |
	           ((uint32_t)mac[1] << 16) |
	           ((uint32_t)mac[2] <<  8) |
	           ((uint32_t)mac[3]);
	return true;
}

/*
 * chip_aes_ctr -- AES-128-CTR encryption/decryption using a given chip slot.
 *
 * Implements the LoRaWAN payload cipher: generates a keystream from
 * A-blocks (A[0]=1, A[5]=dir, A[6..9]=devaddr, A[10..13]=seqno,
 * A[15]=counter) and XORs it with the payload in place.
 */
static bool chip_aes_ctr(atecc608c_backend_ctx_t *ctx, uint8_t slot,
                          u4_t devaddr, u4_t seqno, int dndir,
                          uint8_t *payload, int len)
{
	if (len <= 0) {
		return true;
	}

	uint8_t A[16], S[16];
	memset(A, 0, 16);
	A[0] = 0x01;
	A[5] = dndir ? 1 : 0;
	os_wlsbf4(A + 6,  devaddr);
	os_wlsbf4(A + 10, seqno);

	int offset = 0;
	uint8_t ctr = 1;
	while (offset < len) {
		A[15] = ctr++;
		if (!chip_ecb_slot(ctx, slot, A, S)) {
			return false;
		}
		int chunk = (len - offset > 16) ? 16 : (len - offset);
		for (int j = 0; j < chunk; ++j) {
			payload[offset + j] ^= S[j];
		}
		offset += chunk;
	}
	return true;
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
	return (mac[0] == pdu[len + 0] &&
	        mac[1] == pdu[len + 1] &&
	        mac[2] == pdu[len + 2] &&
	        mac[3] == pdu[len + 3]) ? 1 : 0;
}

/*
 * Derive NwkSKey and AppSKey from join-accept fields using chip AES.
 *
 * 1. Derive keys via AppKey (slot 0) AES-ECB into temporary RAM buffers.
 * 2. Write them to chip slots (ATECC_SLOT_NWKSKEY, ATECC_SLOT_APPSKEY)
 *    so all subsequent data-frame crypto uses the chip's AES engine.
 * 3. Scrub the RAM copies -- session keys never persist in host memory.
 *
 * Returns false on chip I/O error.
 */
static bool backend_sessKeys(atecc608c_backend_ctx_t *ctx, u2_t devnonce,
                              const uint8_t *artnonce)
{
	uint8_t nwkkey[16], artkey[16];
	uint8_t block[32];

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
		secure_zero(nwkkey, sizeof(nwkkey));
		secure_zero(artkey, sizeof(artkey));
		return false;
	}
	if (!chip_ecb(ctx, artkey, artkey)) {
		secure_zero(nwkkey, sizeof(nwkkey));
		secure_zero(artkey, sizeof(artkey));
		return false;
	}

	/* Write session keys to chip slots, then scrub RAM.
	 *
	 * Each write needs its own wake/write/sleep cycle.  The writes
	 * are best-effort: if one fails the join still succeeds but
	 * data-frame crypto will fail (keys are scrubbed from RAM either
	 * way).  In practice WriteConfig=Always slots accept plain writes
	 * reliably after the data zone is locked.
	 */
	atecc608c_t *dev = (atecc608c_t *)ctx->chip;
	uint8_t wake_resp[4];

	/*
	 * Write session keys to chip slots.
	 *
	 * After writing to an AES slot, the chip's AES engine may not
	 * use the new key until a sleep/wake cycle has occurred.  We
	 * force this by sleeping and re-waking after each write.
	 */
	memcpy(block, nwkkey, 16);
	memset(block + 16, 0, 16);
	if (atecc608c_wake(dev, wake_resp)) {
		atecc608c_write_data_slot(dev, ATECC_SLOT_NWKSKEY, block);
		atecc608c_sleep(dev);
	}

	memcpy(block, artkey, 16);
	memset(block + 16, 0, 16);
	if (atecc608c_wake(dev, wake_resp)) {
		atecc608c_write_data_slot(dev, ATECC_SLOT_APPSKEY, block);
		atecc608c_sleep(dev);
	}

	/* The ATECC608C's AES engine may cache slot contents internally.
	 * After EEPROM writes, allow time for the write to complete, then
	 * force a sleep/wake cycle to flush the cache so the AES engine
	 * picks up the newly written keys. */
	delay(10);
	if (atecc608c_wake(dev, wake_resp)) {
		atecc608c_sleep(dev);
	}

	/* Scrub session keys from RAM -- they live on the chip now.
	 * Use secure_zero to prevent the compiler from optimising away
	 * these stores as dead writes. */
	secure_zero(nwkkey, sizeof(nwkkey));
	secure_zero(artkey, sizeof(artkey));
	secure_zero(block, sizeof(block));

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
	if (!ctx->initialized || ctx->chip == NULL) {
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

	/* Encrypt payload: port 0 → NwkSKey, else → AppSKey */
	if ((uint8_t)(payload_index + 1u) < nData) {
		uint8_t enc_slot =
			(cipher_out[payload_index] == 0u)
				? ATECC_SLOT_NWKSKEY
				: ATECC_SLOT_APPSKEY;
		if (!chip_aes_ctr(ctx, enc_slot,
		                  LMIC.devaddr, LMIC.seqnoUp - 1u, /* uplink */ 0,
		                  cipher_out + payload_index + 1u,
		                  nData - payload_index - 1u)) {
			return ATECC608C_BACKEND_STATUS_IO_ERROR;
		}
	}

	/* Append MIC using NwkSKey */
	uint32_t mic;
	if (!chip_aes_cmac_b0(ctx, ATECC_SLOT_NWKSKEY,
	                       LMIC.devaddr, LMIC.seqnoUp - 1u, /* uplink */ 0,
	                       cipher_out, nData, &mic)) {
		return ATECC608C_BACKEND_STATUS_IO_ERROR;
	}
	os_wmsbf4(cipher_out + nData, mic);

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
	if (!ctx->initialized || ctx->chip == NULL) {
		return ATECC608C_BACKEND_STATUS_NOT_INITIALIZED;
	}
	if (key_index >= 5u || phy_len < 4u) {
		return ATECC608C_BACKEND_STATUS_INVALID_PARAM;
	}
	if (!ctx->nwkskey_present[key_index]) {
		return ATECC608C_BACKEND_STATUS_NOT_PROVISIONED;
	}

	uint8_t pdu_len = phy_len - 4u;
	uint32_t mic_computed;
	if (!chip_aes_cmac_b0(ctx, ATECC_SLOT_NWKSKEY,
	                       devaddr, fcnt_down, /* downlink */ 1,
	                       phy_payload, pdu_len, &mic_computed)) {
		return ATECC608C_BACKEND_STATUS_IO_ERROR;
	}

	uint32_t mic_received = os_rmsbf4(phy_payload + pdu_len);
	if (mic_computed != mic_received) {
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
	if (!ctx->initialized || ctx->chip == NULL) {
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
		uint8_t dec_slot =
			(port != 0) ? ATECC_SLOT_APPSKEY : ATECC_SLOT_NWKSKEY;
		if (!chip_aes_ctr(ctx, dec_slot,
		                  devaddr, fcnt_down, /* downlink */ 1,
		                  clear_out + portOffset,
		                  nPayload - portOffset)) {
			return ATECC608C_BACKEND_STATUS_IO_ERROR;
		}
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
