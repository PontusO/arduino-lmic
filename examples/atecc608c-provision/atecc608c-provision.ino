/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C Stage 1 provisioning sketch -- config zone write and lock.
 *
 * PURPOSE
 * -------
 * This sketch programs the ATECC608C configuration zone with the Ilabs
 * LoRaWAN slot layout and then locks it.  Locking the config zone is a
 * prerequisite for:
 *
 *   - True hardware random number generation (the Random command returns a
 *     fixed sequence on unlocked devices).
 *   - Enforcing key access policies after the data zone is locked (Stage 3).
 *
 * SLOT LAYOUT
 * -----------
 *   Slot 0  AppKey      AES-128  Write-once at factory; never readable.
 *   Slot 1  NwkSKey     AES-128  Encrypted write (auth: slot 3); never readable.
 *   Slot 2  AppSKey     AES-128  Encrypted write (auth: slot 3); never readable.
 *   Slot 3  Auth key    AES-128  Write-once at factory; never readable.
 *                                Authorises encrypted writes to slots 1 and 2
 *                                after the data zone is locked (Stage 3).
 *   4-15    Reserved    --       Never writable; never readable.
 *
 * NOTE: The access policies encoded in SlotConfig / KeyConfig only take
 * effect after the DATA zone is locked (Stage 3).  Before the data zone is
 * locked all slots can be freely written in clear text, which is the
 * intended factory provisioning flow.
 *
 * SAFETY
 * ------
 * Locking the config zone is IRREVERSIBLE.  This sketch includes multiple
 * safeguards:
 *
 *   1. It reads and displays the current config zone before making any
 *      changes so you can verify the chip's factory state.
 *   2. It aborts immediately if the zone is already locked.
 *   3. After writing, it reads the zone back and compares it word-by-word
 *      against the intended template before locking.
 *   4. The Lock command is issued with a CRC computed over the actual zone
 *      contents; the chip rejects the lock if the CRC does not match.
 *   5. The lock step requires explicit serial confirmation ("YES\n").
 *
 * DEVICE IDENTITY
 * ---------------
 * The ATECC608C has a factory-unique 9-byte serial number stored in bytes
 * 0-3 and 8-12 of the config zone.  This sketch prints the serial number
 * so it can be recorded in the factory provisioning database and used to
 * associate the chip with its per-device AppKey.
 *
 * PREREQUISITES
 * -------------
 *   - ATECC608C wired to the default I2C bus at address 0x60.
 *   - Serial monitor open at 115200 baud.
 *   - No LMIC radio hardware required.
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
void onEvent(ev_t ev)        { (void)ev;  }

/* ---- ATECC608C configuration --------------------------------------------- */

#define ATECC608C_ADDR       0x60
#define ATECC608C_RESET_PIN  (-1)
#define ATECC608C_I2C_HZ     100000UL

static atecc608c_t dev;

/* ---- Config zone template ------------------------------------------------
 *
 * This array covers bytes 16..127 of the config zone (the writable region).
 * Bytes 0..15 are factory-programmed (serial number, revision number) and
 * are read back from the chip; they are never overwritten.
 *
 * The template is written in 4-byte words.  Bytes 84..91 (UserExtra,
 * LockValue, LockConfig, SlotLocked, ChipOptions) are skipped -- the lock
 * bytes are managed exclusively by the Lock command, and the others are
 * left at their factory defaults.
 *
 * SlotConfig bit layout (2 bytes per slot, little-endian):
 *   Low byte  bits [3:0]  ReadKey       -- key slot for encrypted reads
 *             bit  [4]    NoMac         -- 0 = MAC operations allowed
 *             bit  [5]    LimitedUse    -- 0 = no use-counter limit
 *             bit  [6]    EncryptRead   -- 0 = reads not encrypted (IsSecret
 *                                          already prevents clear reads)
 *             bit  [7]    IsSecret      -- 1 = slot holds a secret
 *   High byte bits [3:0]  WriteKey      -- slot index of key authorising writes
 *             bits [7:4]  WriteConfig   -- 0x0 Always / 0x2 Never / 0x3 Encrypt
 *
 * KeyConfig bit layout (2 bytes per slot, little-endian):
 *   Low byte  bit  [0]    Private       -- 0 = AES / symmetric key (not ECC)
 *             bit  [1]    PubInfo       -- 0
 *             bits [4:2]  KeyType       -- 0b110 (6) = AES-128 key
 *             bit  [5]    Lockable      -- 1 = slot can be individually locked
 *             bit  [6]    ReqRandom     -- 0 = no random nonce required
 *             bit  [7]    ReqAuth       -- 0 = no prior authorisation required
 *   High byte bits [3:0]  AuthKey       -- 0 (not used)
 *             bit  [4]    IntrusionDisable -- 0
 *             bits [15:13] X509id       -- 0
 * -------------------------------------------------------------------------- */

/*
 * Slot 0 (AppKey) SlotConfig: IsSecret=1, WriteConfig=Never(0x2), WriteKey=0
 *   Low byte  = 0x80  (IsSecret=1, all others 0)
 *   High byte = 0x20  (WriteConfig=0x2 in [7:4], WriteKey=0 in [3:0])
 */
#define SLOTCFG_APPKEY_LO   0x80u
#define SLOTCFG_APPKEY_HI   0x20u

/*
 * Slot 1/2 (NwkSKey / AppSKey) SlotConfig:
 *   IsSecret=1, WriteConfig=Encrypt(0x3), WriteKey=3 (auth key slot)
 *   Low byte  = 0x80
 *   High byte = 0x33  (WriteConfig=0x3 in [7:4], WriteKey=3 in [3:0])
 */
#define SLOTCFG_SESSKEY_LO  0x80u
#define SLOTCFG_SESSKEY_HI  0x33u

/*
 * Slot 3 (Auth key) SlotConfig: IsSecret=1, WriteConfig=Never, WriteKey=0
 *   Same encoding as AppKey.
 */
#define SLOTCFG_AUTHKEY_LO  0x80u
#define SLOTCFG_AUTHKEY_HI  0x20u

/*
 * Slots 4-15 (Reserved) SlotConfig: IsSecret=0, WriteConfig=Never, WriteKey=0
 *   Low byte  = 0x00
 *   High byte = 0x20
 */
#define SLOTCFG_UNUSED_LO   0x00u
#define SLOTCFG_UNUSED_HI   0x20u

/*
 * KeyConfig for AES-128 key slots (slots 0-3):
 *   Private=0, PubInfo=0, KeyType=6(AES), Lockable=1, ReqRandom=0, ReqAuth=0
 *   Low byte  = (1<<5) | (6<<2) = 0x20 | 0x18 = 0x38
 *   High byte = 0x00
 */
#define KEYCFG_AES_LO       0x38u
#define KEYCFG_AES_HI       0x00u

/*
 * KeyConfig for unused slots (4-15):
 *   KeyType=7 (SHA/HMAC, generic), Lockable=1
 *   Low byte  = (1<<5) | (7<<2) = 0x20 | 0x1C = 0x3Cu
 *   High byte = 0x00
 */
#define KEYCFG_UNUSED_LO    0x3Cu
#define KEYCFG_UNUSED_HI    0x00u

/*
 * The full template for bytes 16..127 (112 bytes).
 * This is compared against the read-back after writing to catch any
 * I2C errors before the irreversible lock step.
 *
 * Bytes 84..91 are skipped during the write loop (see provisioning logic
 * below) and are therefore not included in this array.  The array covers:
 *   [0..67]   = config zone bytes 16..83
 *   [68..79]  = config zone bytes 92..103  (X509format + KeyConfig[0..3])
 *   [80..111] = config zone bytes 104..127 (KeyConfig[4..15])
 */
static const uint8_t k_template_16_83[68] = {
	/* Byte 16 */ 0xC0u,              /* I2C_Address = 0x60 << 1 */
	/* Byte 17 */ 0x00u,              /* Reserved */
	/* Byte 18 */ 0xAAu,              /* OTPmode: consumption mode (standard) */
	/* Byte 19 */ 0x00u,              /* ChipMode: default */

	/* Bytes 20-21: SlotConfig[0]  AppKey  (write-once, never readable) */
	SLOTCFG_APPKEY_LO,  SLOTCFG_APPKEY_HI,
	/* Bytes 22-23: SlotConfig[1]  NwkSKey (encrypted write via slot 3) */
	SLOTCFG_SESSKEY_LO, SLOTCFG_SESSKEY_HI,
	/* Bytes 24-25: SlotConfig[2]  AppSKey (encrypted write via slot 3) */
	SLOTCFG_SESSKEY_LO, SLOTCFG_SESSKEY_HI,
	/* Bytes 26-27: SlotConfig[3]  Auth key (write-once, never readable) */
	SLOTCFG_AUTHKEY_LO, SLOTCFG_AUTHKEY_HI,
	/* Bytes 28-29: SlotConfig[4]  Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 30-31: SlotConfig[5]  Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 32-33: SlotConfig[6]  Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 34-35: SlotConfig[7]  Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 36-37: SlotConfig[8]  Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 38-39: SlotConfig[9]  Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 40-41: SlotConfig[10] Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 42-43: SlotConfig[11] Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 44-45: SlotConfig[12] Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 46-47: SlotConfig[13] Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 48-49: SlotConfig[14] Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,
	/* Bytes 50-51: SlotConfig[15] Reserved */
	SLOTCFG_UNUSED_LO,  SLOTCFG_UNUSED_HI,

	/* Bytes 52-59: Counter[0] -- monotonic counter, initialised to 0 */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
	/* Bytes 60-67: Counter[1] -- monotonic counter, initialised to 0 */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,

	/* Bytes 68-83: UseLock, VolatileKeyPermission, SecureBoot,
	 *              KdfIvLoc, KdfIvStr, Reserved -- all default 0 */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
};

/* Bytes 92..127 (skipping 84..91 which contain lock bytes). */
static const uint8_t k_template_92_127[36] = {
	/* Bytes 92-95: X509format -- not used, all zeros */
	0x00u, 0x00u, 0x00u, 0x00u,

	/* Bytes 96-97:   KeyConfig[0]  AppKey  (AES-128) */
	KEYCFG_AES_LO,    KEYCFG_AES_HI,
	/* Bytes 98-99:   KeyConfig[1]  NwkSKey (AES-128) */
	KEYCFG_AES_LO,    KEYCFG_AES_HI,
	/* Bytes 100-101: KeyConfig[2]  AppSKey (AES-128) */
	KEYCFG_AES_LO,    KEYCFG_AES_HI,
	/* Bytes 102-103: KeyConfig[3]  Auth key (AES-128) */
	KEYCFG_AES_LO,    KEYCFG_AES_HI,
	/* Bytes 104-105: KeyConfig[4]  Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 106-107: KeyConfig[5]  Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 108-109: KeyConfig[6]  Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 110-111: KeyConfig[7]  Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 112-113: KeyConfig[8]  Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 114-115: KeyConfig[9]  Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 116-117: KeyConfig[10] Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 118-119: KeyConfig[11] Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 120-121: KeyConfig[12] Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 122-123: KeyConfig[13] Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 124-125: KeyConfig[14] Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
	/* Bytes 126-127: KeyConfig[15] Reserved */
	KEYCFG_UNUSED_LO, KEYCFG_UNUSED_HI,
};

/* ---- Utility helpers ----------------------------------------------------- */

static void printHex(uint8_t b)
	{
	if (b < 0x10)
		Serial.print('0');
	Serial.print(b, HEX);
	}

/*
 * Print a hex dump of buf[len] with byte_offset labels, 16 bytes per row.
 */
static void printHexDump(const uint8_t *buf, uint8_t len, uint8_t start_offset)
	{
	for (uint8_t i = 0; i < len; ++i)
		{
		if ((i % 16) == 0)
			{
			Serial.print(F("  ["));
			printHex((uint8_t)(start_offset + i));
			Serial.print(F("] "));
			}
		printHex(buf[i]);
		Serial.print(' ');
		if ((i % 16) == 15 || i == len - 1)
			Serial.println();
		}
	}

/*
 * Print the factory serial number extracted from the config zone.
 *
 * The ATECC608C serial number is 9 bytes split across the config zone:
 *   SN[0:3] = bytes 0-3  (bytes 0-1 are always 0x01 0x23 for ATECC devices)
 *   SN[4:8] = bytes 8-12
 *
 * Bytes 4-7 are the 4-byte revision number, not part of the serial.
 */
static void printSerialNumber(const uint8_t *cfg)
	{
	Serial.print(F("  Serial: "));
	for (uint8_t i = 0; i < 4; ++i)
		{
		printHex(cfg[i]);
		Serial.print(' ');
		}
	for (uint8_t i = 8; i <= 12; ++i)
		{
		printHex(cfg[i]);
		if (i < 12)
			Serial.print(' ');
		}
	Serial.println();
	Serial.print(F("  Revision: "));
	for (uint8_t i = 4; i < 8; ++i)
		{
		printHex(cfg[i]);
		if (i < 7)
			Serial.print(' ');
		}
	Serial.println();
	}

/*
 * Block until the user types "YES" (case-sensitive) followed by Enter.
 * Any other input restarts the prompt.  This guards the irreversible
 * lock step against accidental button-presses.
 */
static bool waitForYes(void)
	{
	Serial.println(F("  Type YES and press Enter to proceed, or reset the board to abort:"));
	char buf[8];
	uint8_t pos = 0;
	memset(buf, 0, sizeof(buf));

	while (true)
		{
		if (Serial.available())
			{
			char c = (char)Serial.read();
			if (c == '\n' || c == '\r')
				{
				buf[pos] = '\0';
				if (strcmp(buf, "YES") == 0)
					return true;
				/* Wrong input -- reset buffer and re-prompt. */
				Serial.println(F("  Not confirmed.  Type YES and press Enter, or reset to abort."));
				pos = 0;
				memset(buf, 0, sizeof(buf));
				}
			else if (pos < (sizeof(buf) - 1))
				{
				buf[pos++] = c;
				}
			}
		}
	}

/* ---- Provisioning steps -------------------------------------------------- */

/*
 * Step 1: Read and display the current config zone.
 * Returns false if the chip cannot be read.
 */
static bool step_read_and_display(uint8_t cfg[128], const char *label)
	{
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: chip did not respond to wake token."));
		return false;
		}

	if (!atecc608c_read_config_zone(&dev, cfg))
		{
		atecc608c_sleep(&dev);
		Serial.println(F("ERROR: failed to read config zone."));
		return false;
		}

	atecc608c_sleep(&dev);

	Serial.println(label);
	printHexDump(cfg, 128, 0);
	return true;
	}

/*
 * Step 2: Write the template into the config zone, word by word.
 *
 * Two regions are written:
 *   bytes 16..83  -- I2C address, ChipMode, OTPmode, SlotConfig, Counters
 *   bytes 92..127 -- X509format, KeyConfig
 *
 * Bytes 84..91 (UserExtra, LockValue, LockConfig, SlotLocked, ChipOptions)
 * are intentionally skipped.  The lock bytes are managed by the Lock command
 * and must not be overwritten via the Write command.
 *
 * Each word write wakes the chip, sends the Write command, and sleeps the
 * chip.  The tEXEC delay (35 ms) is built into atecc608c_write_config_word().
 */
static bool step_write_template(void)
	{
	Serial.println(F("\nWriting config zone template..."));

	/* Region A: bytes 16..83 */
	for (uint8_t offset = 16u; offset < 84u; offset += 4u)
		{
		const uint8_t *word = &k_template_16_83[offset - 16u];

		uint8_t wake_resp[4];
		if (!atecc608c_wake(&dev, wake_resp))
			{
			Serial.print(F("ERROR: wake failed before writing byte "));
			Serial.println(offset);
			return false;
			}

		if (!atecc608c_write_config_word(&dev, offset, word))
			{
			atecc608c_sleep(&dev);
			Serial.print(F("ERROR: write failed at byte offset "));
			Serial.println(offset);
			return false;
			}

		atecc608c_sleep(&dev);

		Serial.print('.');
		}

	/* Region B: bytes 92..127 (skip 84..91) */
	for (uint8_t offset = 92u; offset < 128u; offset += 4u)
		{
		const uint8_t *word = &k_template_92_127[offset - 92u];

		uint8_t wake_resp[4];
		if (!atecc608c_wake(&dev, wake_resp))
			{
			Serial.print(F("ERROR: wake failed before writing byte "));
			Serial.println(offset);
			return false;
			}

		if (!atecc608c_write_config_word(&dev, offset, word))
			{
			atecc608c_sleep(&dev);
			Serial.print(F("ERROR: write failed at byte offset "));
			Serial.println(offset);
			return false;
			}

		atecc608c_sleep(&dev);

		Serial.print('.');
		}

	Serial.println(F(" done."));
	return true;
	}

/*
 * Step 3: Read the config zone back and verify it matches the template.
 *
 * Bytes 0..15 are factory bytes (cannot be written -- not checked against
 * template).  Bytes 84..91 were not written and are not verified.
 * All other bytes must match exactly.
 *
 * Returns false if any mismatch is found.
 */
static bool step_verify(const uint8_t cfg[128])
	{
	Serial.println(F("\nVerifying written config zone..."));

	bool ok = true;

	/* Check region A: bytes 16..83 */
	for (uint8_t i = 0; i < 68u; ++i)
		{
		uint8_t offset = 16u + i;
		if (cfg[offset] != k_template_16_83[i])
			{
			Serial.print(F("  MISMATCH at byte "));
			Serial.print(offset);
			Serial.print(F(":  expected 0x"));
			printHex(k_template_16_83[i]);
			Serial.print(F("  got 0x"));
			printHex(cfg[offset]);
			Serial.println();
			ok = false;
			}
		}

	/* Check region B: bytes 92..127 */
	for (uint8_t i = 0; i < 36u; ++i)
		{
		uint8_t offset = 92u + i;
		if (cfg[offset] != k_template_92_127[i])
			{
			Serial.print(F("  MISMATCH at byte "));
			Serial.print(offset);
			Serial.print(F(":  expected 0x"));
			printHex(k_template_92_127[i]);
			Serial.print(F("  got 0x"));
			printHex(cfg[offset]);
			Serial.println();
			ok = false;
			}
		}

	if (ok)
		Serial.println(F("  All written bytes verified OK."));

	return ok;
	}

/*
 * Step 4: Lock the config zone.
 *
 * Computes CRC-16/IBM over all 128 bytes of the zone as read back from the
 * chip (including factory bytes 0..15 that we did not write).  Passes the
 * CRC to atecc608c_lock_config_zone() so the chip can validate it before
 * sealing.
 */
static bool step_lock(const uint8_t cfg[128])
	{
	uint16_t summary_crc = atecc608c_crc16(cfg, 128u);

	Serial.print(F("\nConfig zone CRC-16: 0x"));
	printHex((uint8_t)(summary_crc >> 8));
	printHex((uint8_t)(summary_crc & 0xFF));
	Serial.println();

	Serial.println(F("\n*** POINT OF NO RETURN ***"));
	Serial.println(F("Locking the config zone is permanent and cannot be undone."));
	Serial.println(F("Verify the hex dump above matches the intended template before continuing."));

	if (!waitForYes())
		return false;

	Serial.println(F("\nSending Lock command..."));

	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: wake failed before lock."));
		return false;
		}

	bool locked = atecc608c_lock_config_zone(&dev, summary_crc);
	atecc608c_sleep(&dev);

	if (!locked)
		{
		Serial.println(F("ERROR: Lock command failed."));
		Serial.println(F("  Possible cause: CRC mismatch (zone changed between read-back and lock)."));
		Serial.println(F("  Reset the board and try again."));
		return false;
		}

	Serial.println(F("Lock command accepted."));
	return true;
	}

/*
 * Step 5: Verify that the zone is now reported as locked.
 */
static bool step_verify_locked(void)
	{
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: wake failed during lock verification."));
		return false;
		}

	bool is_locked = false;
	bool ok = atecc608c_config_zone_is_locked(&dev, &is_locked);
	atecc608c_sleep(&dev);

	if (!ok)
		{
		Serial.println(F("ERROR: could not read LockConfig byte."));
		return false;
		}

	if (!is_locked)
		{
		Serial.println(F("ERROR: config zone reports as UNLOCKED after lock command!"));
		return false;
		}

	Serial.println(F("Config zone confirmed LOCKED."));
	return true;
	}

/*
 * Step 6: Test the hardware RNG.
 *
 * The Random command should now return true random data.  We issue two calls
 * and verify the outputs are different.  On an unlocked chip both calls would
 * return the same fixed pattern; on a locked chip they should differ.
 */
static void step_test_rng(void)
	{
	Serial.println(F("\n--- Hardware RNG test (should now produce true random data) ---"));

	uint8_t rnd1[32], rnd2[32];
	uint8_t wake_resp[4];

	/* First call */
	if (!atecc608c_wake(&dev, wake_resp) ||
	    !atecc608c_random_bytes(&dev, rnd1, sizeof(rnd1)))
		{
		atecc608c_sleep(&dev);
		Serial.println(F("  ERROR: RNG call 1 failed."));
		return;
		}
	atecc608c_sleep(&dev);

	Serial.print(F("  RNG[0]: "));
	for (uint8_t i = 0; i < 32; ++i)
		{
		printHex(rnd1[i]);
		Serial.print(' ');
		}
	Serial.println();

	delay(5); /* short gap between sleep and next wake */

	/* Second call */
	if (!atecc608c_wake(&dev, wake_resp) ||
	    !atecc608c_random_bytes(&dev, rnd2, sizeof(rnd2)))
		{
		atecc608c_sleep(&dev);
		Serial.println(F("  ERROR: RNG call 2 failed."));
		return;
		}
	atecc608c_sleep(&dev);

	Serial.print(F("  RNG[1]: "));
	for (uint8_t i = 0; i < 32; ++i)
		{
		printHex(rnd2[i]);
		Serial.print(' ');
		}
	Serial.println();

	if (memcmp(rnd1, rnd2, 32) != 0)
		Serial.println(F("  PASS  outputs differ -- true random number generation confirmed."));
	else
		Serial.println(F("  FAIL  outputs are identical -- RNG may not be working correctly."));
	}

/* ---- Main ---------------------------------------------------------------- */

void setup()
	{
	Serial.begin(115200);
	while (!Serial)
		;

	Serial.println(F("\r\nATECC608C Config Zone Provisioning"));
	Serial.println(F("===================================="));
	Serial.println(F("Stage 1: Write and lock the configuration zone."));
	Serial.println();

	/* Initialise the ATECC608C. */
	if (!atecc608c_init(&dev, &Wire, ATECC608C_ADDR,
	                    ATECC608C_RESET_PIN, ATECC608C_I2C_HZ))
		{
		Serial.println(F("FATAL: atecc608c_init failed -- check wiring and I2C address."));
		return;
		}

	Serial.println(F("Chip detected and awake."));

	/* --- Step 1a: Read and display current config zone --- */
	uint8_t cfg[128];
	if (!step_read_and_display(cfg, "\nCurrent config zone (before write):"))
		return;

	/* Print the chip serial number for the factory database. */
	Serial.println();
	printSerialNumber(cfg);

	/* --- Step 1b: Abort if already locked --- */
	{
	bool is_locked = false;
	uint8_t wake_resp[4];
	atecc608c_wake(&dev, wake_resp);
	bool ok = atecc608c_config_zone_is_locked(&dev, &is_locked);
	atecc608c_sleep(&dev);

	if (!ok)
		{
		Serial.println(F("\nERROR: could not read lock status -- aborting."));
		return;
		}
	if (is_locked)
		{
		Serial.println(F("\nConfig zone is ALREADY LOCKED.  Nothing to do."));
		Serial.println(F("If you need to re-provision this chip, it must be replaced."));
		step_test_rng(); /* still run the RNG test to confirm it works */
		return;
		}
	}

	Serial.println(F("\nConfig zone is unlocked.  Proceeding with provisioning."));

	/* --- Step 2: Write the template --- */
	if (!step_write_template())
		return;

	/* --- Step 3: Read back and verify --- */
	if (!step_read_and_display(cfg, "\nConfig zone after write:"))
		return;

	if (!step_verify(cfg))
		{
		Serial.println(F("\nERROR: verification failed -- config zone was NOT locked."));
		Serial.println(F("Correct the mismatch and retry."));
		return;
		}

	/* --- Step 4: Lock (requires explicit user confirmation) --- */
	if (!step_lock(cfg))
		return;

	/* --- Step 5: Confirm locked --- */
	if (!step_verify_locked())
		return;

	/* --- Step 6: Test RNG --- */
	step_test_rng();

	/* --- Done --- */
	Serial.println(F("\n===================================="));
	Serial.println(F("Provisioning complete."));
	Serial.println(F("Record the serial number above in the factory database."));
	Serial.println(F("The chip is now ready for key injection (Stage 2)."));
	}

void loop()
	{
	/* All work is done in setup(). */
	}
