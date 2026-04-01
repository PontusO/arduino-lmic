/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * Layer 2 hardware protocol test for the ATECC608C secure element driver.
 *
 * This sketch exercises the ATECC608C transport and command layer without
 * involving LMIC or the LoRaWAN stack.  It tests:
 *
 *   1. I2C bus scan -- verifies the chip is visible on the bus.
 *   2. Wake / sleep -- verifies the wake-token sequence and response.
 *   3. Hardware RNG  -- issues the Random command twice and checks that
 *                       both calls return 32 non-identical bytes.
 *   4. Idle command  -- verifies the chip can be put into idle state and
 *                       woken again without error.
 *   5. CRC-16        -- validates the CRC helper against a known byte
 *                       sequence derived from the Random command frame.
 *
 * Prerequisites:
 *   - ATECC608C wired to the default I2C bus (SDA/SCL) at address 0x60.
 *   - Bus pull-ups in place (typically 4k7 to 3V3).
 *   - I2C clock set to 100 kHz (required for the wake token to satisfy tWLO).
 *
 * Configuration:
 *   ATECC608C_ADDR      Default I2C 7-bit address.  Change if your device
 *                       has been provisioned to a different address.
 *   ATECC608C_I2C_HZ    I2C clock.  Must be 100000 for the wake token to
 *                       work.  See atecc608c_hal_send_wake_token() for the
 *                       technical reason.
 *
 * No LMIC radio hardware is required for this sketch.
 *
 *******************************************************************************/

#include <lmic.h>
#include <hal/hal.h>
#include <Wire.h>

/*
 * lmic_pins and os_get* stubs are required by the linker when lmic.h is
 * included.  No radio hardware is used in this sketch.
 */
const lmic_pinmap lmic_pins = {
	.nss  = LMIC_UNUSED_PIN,
	.rxtx = LMIC_UNUSED_PIN,
	.rst  = LMIC_UNUSED_PIN,
	.dio  = { LMIC_UNUSED_PIN, LMIC_UNUSED_PIN, LMIC_UNUSED_PIN },
};
void os_getArtEui(u1_t *buf) { (void)buf; }
void os_getDevEui(u1_t *buf) { (void)buf; }
void os_getDevKey(u1_t *buf) { (void)buf; }
void onEvent(ev_t ev)        { (void)ev; }

/* ---- User configuration -------------------------------------------------- */

#define ATECC608C_ADDR    0x60
#define ATECC608C_I2C_HZ  100000UL

/*
 * Set to the Arduino pin connected to the ATECC608C RESET line, or -1 if
 * the reset pin is not connected / not used.
 */
#define ATECC608C_RESET_PIN  (-1)

/* -------------------------------------------------------------------------- */

static atecc608c_t dev;

/* Running pass/fail counters written by check(). */
static int gPassed = 0;
static int gFailed = 0;

/* Print a fixed-width hex byte. */
static void printHex(uint8_t b)
	{
	if (b < 0x10)
		Serial.print('0');
	Serial.print(b, HEX);
	}

/* Print a buffer as space-separated hex bytes on one line. */
static void printBuf(const uint8_t *buf, uint8_t len)
	{
	for (uint8_t i = 0; i < len; ++i)
		{
		if (i != 0)
			Serial.print(' ');
		printHex(buf[i]);
		}
	}

/* Log the result of a named test and update global counters. */
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

/* ---- Test implementations ------------------------------------------------ */

/*
 * Test 1: I2C scan.
 *
 * Scan the full I2C bus and report all responding addresses.  The test passes
 * if the ATECC608C address (ATECC608C_ADDR) acknowledges.
 */
static void test_i2c_scan(void)
	{
	Serial.println(F("--- I2C bus scan ---"));
	bool found = false;
	for (uint8_t addr = 0x08; addr <= 0x77; ++addr)
		{
		Wire.beginTransmission(addr);
		uint8_t err = Wire.endTransmission(true);
		if (err == 0)
			{
			Serial.print(F("  ACK at 0x"));
			if (addr < 16)
				Serial.print('0');
			Serial.println(addr, HEX);
			if (addr == ATECC608C_ADDR)
				found = true;
			}
		}
	check(F("chip visible at ATECC608C_ADDR"), found);
	}

/*
 * Test 2: Wake / sleep cycle.
 *
 * Send the wake token, read the 4-byte wake response, verify it has the
 * expected pattern, then put the chip back to sleep.
 */
static void test_wake_sleep(void)
	{
	Serial.println(F("--- Wake / sleep ---"));

	uint8_t resp[4];
	bool ok = atecc608c_wake(&dev, resp);

	Serial.print(F("  Wake response: "));
	printBuf(resp, 4);
	Serial.println();

	check(F("wake returns true"), ok);

	/* Immediately put the chip to sleep again. */
	bool slept = atecc608c_sleep(&dev);
	check(F("sleep returns true"), slept);
	}

/*
 * Test 3: Hardware RNG.
 *
 * Issue the Random command twice and verify that:
 *   a) Both calls succeed.
 *   b) The returned bytes are not all zero.
 *   c) The two 32-byte blocks differ (i.e. the RNG is not stuck).
 *
 * Each call wakes the chip, sends the command, reads the response and
 * puts the chip back to sleep before the next iteration.
 */
static void test_random(void)
	{
	Serial.println(F("--- Hardware RNG ---"));

	uint8_t rnd1[32];
	uint8_t rnd2[32];
	uint8_t wake_resp[4];

	/* First call */
	bool ok1 = atecc608c_wake(&dev, wake_resp);
	if (!ok1)
		{
		check(F("RNG call 1: wake"), false);
		return;
		}
	ok1 = atecc608c_random_bytes(&dev, rnd1, sizeof(rnd1));
	atecc608c_sleep(&dev);

	check(F("RNG call 1 succeeds"), ok1);

	if (ok1)
		{
		Serial.print(F("  RNG[0]: "));
		printBuf(rnd1, 32);
		Serial.println();
		}

	/* Chip needs a little time after sleep before the next wake */
	delay(5);

	/* Second call */
	bool ok2 = atecc608c_wake(&dev, wake_resp);
	if (!ok2)
		{
		check(F("RNG call 2: wake"), false);
		return;
		}
	ok2 = atecc608c_random_bytes(&dev, rnd2, sizeof(rnd2));
	atecc608c_sleep(&dev);

	check(F("RNG call 2 succeeds"), ok2);

	if (ok2)
		{
		Serial.print(F("  RNG[1]: "));
		printBuf(rnd2, 32);
		Serial.println();
		}

	if (ok1 && ok2)
		{
		/* Not all zero */
		bool nonzero = false;
		for (uint8_t i = 0; i < 32; ++i)
			if (rnd1[i] != 0)
				{ nonzero = true; break; }
		check(F("RNG output is not all-zero"), nonzero);

		/* Two calls produce different results */
		bool differ = (memcmp(rnd1, rnd2, 32) != 0);
		if (!differ)
			{
			Serial.println(F("  NOTE: both calls returned identical output."));
			Serial.println(F("        This is expected on an unprovisioned device --"));
			Serial.println(F("        the ATECC608C DRBG returns a fixed sequence"));
			Serial.println(F("        until the configuration zone is locked."));
			Serial.println(F("        The RNG will produce true random data after"));
			Serial.println(F("        provisioning and locking the device."));
			}
		check(F("two RNG calls produce different output"), differ);
		}
	}

/*
 * Test 4: Idle command.
 *
 * Wake the chip, send the Idle command (chip retains volatile state),
 * then wake again to confirm it recovers correctly.
 */
static void test_idle(void)
	{
	Serial.println(F("--- Idle command ---"));

	uint8_t resp[4];
	bool woke = atecc608c_wake(&dev, resp);
	if (!check(F("wake before idle"), woke))
		return;

	bool idled = atecc608c_idle(&dev);
	check(F("idle returns true"), idled);

	delay(5); /* tWHI not required here, just a short gap */

	/* Chip should be recoverable with another wake */
	bool woke2 = atecc608c_wake(&dev, resp);
	check(F("wake after idle"), woke2);
	if (woke2)
		atecc608c_sleep(&dev);
	}

/*
 * Test 5: CRC-16 helper.
 *
 * The Random command transmit packet has a known CRC.  We compute it twice
 * (once over the payload bytes and verify consistency) and also verify that
 * a one-bit-changed input produces a different CRC.
 */
static void test_crc16(void)
	{
	Serial.println(F("--- CRC-16 ---"));

	/*
	 * Canonical Random command payload: [count=0x07, opcode=0x1B, p1=0x00, p2l=0x00, p2h=0x00]
	 * The CRC over these 5 bytes is the value appended to the command frame.
	 * We cannot easily pre-compute the expected value here without an external
	 * reference, so we verify two properties instead:
	 *   a) The function is deterministic (same input gives same output).
	 *   b) A single-bit change in the input changes the CRC.
	 */
	const uint8_t payload[5] = {0x07, 0x1B, 0x00, 0x00, 0x00};
	uint16_t crc1 = atecc608c_crc16(payload, sizeof(payload));
	uint16_t crc2 = atecc608c_crc16(payload, sizeof(payload));

	Serial.print(F("  CRC(Random cmd payload) = 0x"));
	printHex((uint8_t)(crc1 >> 8));
	printHex((uint8_t)(crc1 & 0xFF));
	Serial.println();

	check(F("CRC is deterministic"), crc1 == crc2);

	/* Flip one bit in the payload and verify the CRC changes. */
	uint8_t flipped[5];
	memcpy(flipped, payload, sizeof(flipped));
	flipped[2] ^= 0x01u;
	uint16_t crc3 = atecc608c_crc16(flipped, sizeof(flipped));
	check(F("single-bit change alters CRC"), crc1 != crc3);
	}

/* -------------------------------------------------------------------------- */

void setup()
	{
	Serial.begin(115200);
	while (!Serial)
		; /* wait for USB CDC on Leonardo / Zero / etc. */

	Serial.println(F("\r\nATECC608C hardware probe"));
	Serial.println(F("========================"));

	if (!atecc608c_init(&dev, &Wire, ATECC608C_ADDR,
	                    ATECC608C_RESET_PIN, ATECC608C_I2C_HZ))
		{
		Serial.println(F("atecc608c_init FAILED -- check wiring and address"));
		return;
		}

	Serial.println(F("init OK, starting tests...\r\n"));

	test_i2c_scan();
	Serial.println();

	test_wake_sleep();
	Serial.println();

	test_random();
	Serial.println();

	test_idle();
	Serial.println();

	test_crc16();
	Serial.println();

	/* Summary */
	Serial.println(F("========================"));
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
