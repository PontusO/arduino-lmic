/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * Layer 3 crypto correctness test for the ATECC608C secure element driver.
 *
 * This sketch exercises the atecc608c_backend crypto functions using LMIC's
 * built-in AES engine.  No ATECC608C hardware is required -- the software
 * PRNG fallback is used for randomness.  A radio module is also not required,
 * though the LMIC library must be configured with a valid region and radio
 * type in project_config/lmic_project_config.h.
 *
 * Tests performed:
 *
 *   1. AES-128 ECB   -- Validates the AES engine against the NIST FIPS-197
 *                       Appendix C test vector (key 00..0f, plaintext 00..ff).
 *
 *   2. Join request  -- Creates a join request with known credentials and
 *                       prints the 23 bytes for optional external verification
 *                       (e.g. via a LoRaWAN frame decoder).  The MIC at bytes
 *                       19..22 should be non-zero.
 *
 *   3. Encode + MIC  -- Builds a minimal uplink frame, calls encode_message
 *                       to encrypt the payload and append a MIC, then verifies
 *                       MIC reproducibility (same key + FCnt → identical MIC)
 *                       and key sensitivity (wrong NwkSKey → different MIC).
 *                       Note: verify_mic is for downlinks only and is not used
 *                       here to verify the uplink MIC.
 *
 * External verification:
 *   The bytes printed for Test 2 can be cross-checked using the online
 *   LoRaWAN packet decoder at https://lorawan-packet-decoder-0ta6puiniaut.runkit.sh/
 *   or any LoRaWAN 1.0.x test tool that supports join request MIC validation.
 *
 * Do not forget to define the radio type correctly in
 * arduino-lmic/project_config/lmic_project_config.h or from your BOARDS.txt.
 *
 *******************************************************************************/

#include <lmic.h>
#include <hal/hal.h>
#include <SPI.h>

/*
 * The lmic_pins struct is required by the linker even though no radio
 * hardware is used in this sketch.  Fill in real values if you want
 * to extend the sketch to do over-the-air operations later.
 */
const lmic_pinmap lmic_pins = {
	.nss  = LMIC_UNUSED_PIN,
	.rxtx = LMIC_UNUSED_PIN,
	.rst  = LMIC_UNUSED_PIN,
	.dio  = { LMIC_UNUSED_PIN, LMIC_UNUSED_PIN, LMIC_UNUSED_PIN },
};

/*
 * os_get* callbacks: not used in this sketch but required by the linker.
 */
void os_getArtEui(u1_t *buf) { (void)buf; }
void os_getDevEui(u1_t *buf) { (void)buf; }
void os_getDevKey(u1_t *buf) { (void)buf; }
void onEvent(ev_t ev) { (void)ev; }

/* ---- Shared test state --------------------------------------------------- */

static atecc608c_backend_ctx_t ctx;
static int gPassed = 0;
static int gFailed = 0;

static void printHex(uint8_t b)
	{
	if (b < 0x10)
		Serial.print('0');
	Serial.print(b, HEX);
	}

static void printBuf(const uint8_t *buf, uint8_t len)
	{
	for (uint8_t i = 0; i < len; ++i)
		{
		if (i != 0)
			Serial.print(' ');
		printHex(buf[i]);
		}
	}

static bool check(const __FlashStringHelper *name, bool passed)
	{
	Serial.print(passed ? F("  PASS") : F("  FAIL"));
	Serial.print(F("  "));
	Serial.println(name);
	if (passed)
		++gPassed;
	else
		++gFailed;
	return passed;
	}

/* ---- Test 1: AES-128 ECB ------------------------------------------------- */

/*
 * NIST FIPS-197, Appendix C.1, AES-128:
 *
 *   Key       = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
 *   Plaintext = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
 *   Ciphertext= 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
 */
static void test_aes128_ecb(void)
	{
	Serial.println(F("--- Test 1: AES-128 ECB (NIST FIPS-197 Appendix C) ---"));

	static const uint8_t key[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	static const uint8_t plaintext[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	static const uint8_t expected[16] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
	};

	uint8_t output[16];
	atecc608c_backend_status_t st =
		atecc608c_backend_aes128_encrypt(&ctx, key, plaintext, output);

	check(F("aes128_encrypt returns OK"), st == ATECC608C_BACKEND_STATUS_OK);

	bool match = (memcmp(output, expected, 16) == 0);
	if (!match)
		{
		Serial.print(F("  Expected: "));
		printBuf(expected, 16);
		Serial.println();
		Serial.print(F("  Got:      "));
		printBuf(output, 16);
		Serial.println();
		}
	check(F("ciphertext matches NIST vector"), match);

	/* In-place variant: output == input should also work */
	uint8_t buf[16];
	memcpy(buf, plaintext, 16);
	atecc608c_backend_aes128_encrypt(&ctx, key, buf, buf);
	check(F("in-place encryption matches"), memcmp(buf, expected, 16) == 0);
	}

/* ---- Test 2: Join request creation --------------------------------------- */

/*
 * Create a join request with fixed credentials, print the 23 raw bytes and
 * verify structural properties:
 *   - byte 0 (MHDR) = 0x00  (HDR_FTYPE_JREQ | HDR_MAJOR_V1)
 *   - bytes 1-8  = AppEUI (little-endian as supplied)
 *   - bytes 9-16 = DevEUI (little-endian as supplied)
 *   - bytes 17-18 = DevNonce (little-endian)
 *   - bytes 19-22 = MIC (should be non-zero for non-zero AppKey)
 *
 * The complete frame can be verified externally with a LoRaWAN frame decoder.
 * Use the AppKey printed below and supply the raw bytes to the tool.
 */
static void test_join_request(void)
	{
	Serial.println(F("--- Test 2: Join request creation ---"));

	/*
	 * Test credentials (not real keys -- chosen for easy visual verification).
	 * AppEUI and DevEUI are stored in little-endian order as required by LMIC.
	 */
	static const uint8_t kAppKey[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	/* AppEUI: 00-00-00-00-00-00-00-01 (big-endian display), reversed here */
	static const uint8_t kAppEUI[8] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	/* DevEUI: 00-00-00-00-00-00-00-02 (big-endian display), reversed here */
	static const uint8_t kDevEUI[8] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	atecc608c_backend_set_appkey(&ctx, kAppKey);
	atecc608c_backend_set_appeui(&ctx, kAppEUI);
	atecc608c_backend_set_deveui(&ctx, kDevEUI);

	/*
	 * Force DevNonce to a known value so the output is reproducible.
	 * LMIC.devNonce is a global; we set it directly here.
	 * create_join_request will increment it after use.
	 */
	LMIC.devNonce = 0x0000;

	uint8_t jr[23];
	atecc608c_backend_status_t st =
		atecc608c_backend_create_join_request(&ctx, jr,
		                                       LMIC_SecureElement_JoinFormat_JoinRequest10);

	check(F("create_join_request returns OK"), st == ATECC608C_BACKEND_STATUS_OK);

	if (st == ATECC608C_BACKEND_STATUS_OK)
		{
		Serial.print(F("  Join request (23 bytes): "));
		printBuf(jr, 23);
		Serial.println();

		Serial.print(F("  AppKey used: "));
		printBuf(kAppKey, 16);
		Serial.println();

		check(F("MHDR = 0x00 (HDR_FTYPE_JREQ)"), jr[0] == 0x00);

		/* AppEUI bytes 1-8 should match kAppEUI */
		check(F("AppEUI field matches"), memcmp(&jr[1], kAppEUI, 8) == 0);

		/* DevEUI bytes 9-16 should match kDevEUI */
		check(F("DevEUI field matches"), memcmp(&jr[9], kDevEUI, 8) == 0);

		/* DevNonce was 0x0000, stored little-endian */
		check(F("DevNonce = 0x0000 (LE)"), jr[17] == 0x00 && jr[18] == 0x00);

		/* MIC must be non-zero for a non-zero key */
		bool mic_nonzero = (jr[19] | jr[20] | jr[21] | jr[22]) != 0;
		check(F("MIC is non-zero"), mic_nonzero);

		/* DevNonce should have been incremented */
		check(F("DevNonce incremented to 1"), LMIC.devNonce == 1);
		}
	}

/* ---- Test 3: Encode message + verify MIC --------------------------------- */

/*
 * Build a minimal uplink data frame, encode it (AES-CTR payload encrypt +
 * AES-CMAC MIC), then verify the MIC passes with the correct key and fails
 * with an incorrect key.
 *
 * Frame layout (17 bytes including 4-byte MIC placeholder):
 *   [0]      MHDR  = 0x40 (HDR_FTYPE_DAUP | HDR_MAJOR_V1, unconfirmed up)
 *   [1-4]    DevAddr = 0x01020304 (LE)
 *   [5]      FCtrl = 0x00
 *   [6-7]    FCnt  = 0x0001 (LE)
 *   [8]      FPort = 0x01
 *   [9-12]   FRMPayload = 0xDE 0xAD 0xBE 0xEF
 *   [13-16]  MIC placeholder (zeroes, filled by encode_message)
 */
static void test_encode_verify(void)
	{
	Serial.println(F("--- Test 3: Encode message + verify MIC ---"));

	static const uint8_t kNwkSKey[16] = {
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
	};
	static const uint8_t kAppSKey[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
	};
	static const uint32_t kDevAddr = 0x01020304UL;
	static const uint32_t kSeqnoUp = 1;

	atecc608c_backend_set_nwkskey(&ctx, 0, kNwkSKey);
	atecc608c_backend_set_appskey(&ctx, 0, kAppSKey);

	LMIC.devaddr = kDevAddr;
	LMIC.seqnoUp = kSeqnoUp;

	/*
	 * Build the uplink frame.  message_len includes the 4 MIC bytes (zeroed
	 * here; encode_message will fill them in).  iPayload is the index of the
	 * FPort byte (payload data follows immediately after).
	 */
	uint8_t frame[17] = {
		0x40,                         /* MHDR */
		0x04, 0x03, 0x02, 0x01,       /* DevAddr LE */
		0x00,                         /* FCtrl */
		0x01, 0x00,                   /* FCnt LE */
		0x01,                         /* FPort */
		0xDE, 0xAD, 0xBE, 0xEF,       /* FRMPayload */
		0x00, 0x00, 0x00, 0x00        /* MIC placeholder */
	};
	const uint8_t iPayload = 8; /* index of FPort byte */
	const uint8_t plaintext[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	uint8_t encoded[17];
	atecc608c_backend_status_t st =
		atecc608c_backend_encode_message(&ctx, frame, sizeof(frame),
		                                  iPayload, encoded,
		                                  /* Unicast */ 0);

	check(F("encode_message returns OK"), st == ATECC608C_BACKEND_STATUS_OK);

	if (st == ATECC608C_BACKEND_STATUS_OK)
		{
		Serial.print(F("  Encoded frame: "));
		printBuf(encoded, 17);
		Serial.println();

		uint8_t mic[4] = { encoded[13], encoded[14], encoded[15], encoded[16] };
		Serial.print(F("  MIC: "));
		printBuf(mic, 4);
		Serial.println();

		bool mic_nonzero = (mic[0] | mic[1] | mic[2] | mic[3]) != 0;
		check(F("MIC is non-zero"), mic_nonzero);

		/*
		 * MIC reproducibility: encoding the same plaintext frame with the
		 * same key and sequence number must produce an identical MIC.
		 * (verify_mic is for downlinks only and cannot be used here.)
		 */
		uint8_t frame2[17] = {
			0x40,
			0x04, 0x03, 0x02, 0x01,
			0x00,
			0x01, 0x00,
			0x01,
			0xDE, 0xAD, 0xBE, 0xEF,
			0x00, 0x00, 0x00, 0x00
		};
		uint8_t encoded2[17];
		LMIC.devaddr = kDevAddr;
		LMIC.seqnoUp = kSeqnoUp;
		atecc608c_backend_encode_message(&ctx, frame2, sizeof(frame2),
		                                  iPayload, encoded2, /* Unicast */ 0);
		check(F("MIC is reproducible (same key + FCnt)"),
		      memcmp(encoded + 13, encoded2 + 13, 4) == 0);

		/*
		 * Key sensitivity: a different NwkSKey must produce a different MIC.
		 */
		static const uint8_t kBadKey[16] = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		};
		uint8_t frame3[17] = {
			0x40,
			0x04, 0x03, 0x02, 0x01,
			0x00,
			0x01, 0x00,
			0x01,
			0xDE, 0xAD, 0xBE, 0xEF,
			0x00, 0x00, 0x00, 0x00
		};
		uint8_t encoded3[17];
		atecc608c_backend_set_nwkskey(&ctx, 0, kBadKey);
		LMIC.devaddr = kDevAddr;
		LMIC.seqnoUp = kSeqnoUp;
		atecc608c_backend_encode_message(&ctx, frame3, sizeof(frame3),
		                                  iPayload, encoded3, /* Unicast */ 0);
		atecc608c_backend_set_nwkskey(&ctx, 0, kNwkSKey); /* restore */
		check(F("wrong NwkSKey produces different MIC"),
		      memcmp(encoded + 13, encoded3 + 13, 4) != 0);

		/* Payload bytes should differ from plaintext (encrypted). */
		bool payload_changed = (memcmp(&encoded[9], plaintext, 4) != 0);
		check(F("payload encrypted (differs from plaintext)"), payload_changed);
		}
	}

/* -------------------------------------------------------------------------- */

void setup()
	{
	Serial.begin(115200);
	while (!Serial)
		;

	Serial.println(F("\r\nATECC608C crypto backend test"));
	Serial.println(F("=============================="));
	Serial.println(F("(No hardware required -- uses software AES engine)"));
	Serial.println();

	atecc608c_backend_init(&ctx);

	test_aes128_ecb();
	Serial.println();

	test_join_request();
	Serial.println();

	test_encode_verify();
	Serial.println();

	/* Summary */
	Serial.println(F("=============================="));
	Serial.print(F("Results: "));
	Serial.print(gPassed);
	Serial.print(F(" passed, "));
	Serial.print(gFailed);
	Serial.println(F(" failed."));
	if (gFailed == 0)
		Serial.println(F("ALL TESTS PASSED"));
	else
		Serial.println(F("*** FAILURES DETECTED ***"));
	}

void loop()
	{
	/* All work is done in setup(). */
	}
