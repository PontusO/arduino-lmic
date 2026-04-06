/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C combined provisioning tool.
 *
 * This sketch combines all three provisioning stages into one interactive
 * tool.  On startup it probes the chip, reports its current state, and
 * presents a menu of available operations based on what has already been
 * done:
 *
 *   [1] Write and lock config zone  (Stage 1)
 *       Programs the ATECC608C configuration zone with the Ilabs LoRaWAN
 *       slot layout and permanently locks it.  This defines the chip's
 *       slot types, access policies, and enables the AES engine.  Must be
 *       done before any other operation.
 *
 *   [2] Inject keys                 (Stage 2)
 *       Writes root keys (AppKey, optionally NwkKey and IO Protection Key)
 *       into the data zone.  Must be done after Stage 1 and before Stage 3.
 *       Session key slots (2-7) are left empty -- firmware writes them
 *       after each OTAA join.
 *
 *   [3] Lock data zone              (Stage 3)
 *       Permanently locks the data zone, activating all slot access
 *       policies.  After this step root keys are sealed and cannot be
 *       read or overwritten.  Session key slots remain writable
 *       (WriteConfig=Always) for firmware use.
 *
 *   [4] Chip status                 (informational)
 *       Displays the config zone hex dump, serial number, lock status,
 *       and tests the hardware RNG.
 *
 * SLOT LAYOUT
 * -----------
 *   Slot  Key                 LoRaWAN   Access after data zone lock
 *   ----  ------------------  --------  --------------------------------
 *    0    AppKey               1.0/1.1  WriteConfig=Never   IsSecret=1
 *    1    NwkKey               1.1      WriteConfig=Never   IsSecret=1
 *    2    NwkSKey/FNwkSIntKey  1.0/1.1  WriteConfig=Always  IsSecret=1
 *    3    SNwkSIntKey          1.1      WriteConfig=Always  IsSecret=1
 *    4    NwkSEncKey           1.1      WriteConfig=Always  IsSecret=1
 *    5    AppSKey              1.0/1.1  WriteConfig=Always  IsSecret=1
 *    6    JSIntKey             1.1      WriteConfig=Always  IsSecret=1
 *    7    JSEncKey             1.1      WriteConfig=Always  IsSecret=1
 *    8    Custom credential 1  user     WriteConfig=Always  IsSecret=1
 *    9    Custom credential 2  user     WriteConfig=Always  IsSecret=1
 *   10    Custom credential 3  user     WriteConfig=Always  IsSecret=1
 *   11    Custom credential 4  user     WriteConfig=Always  IsSecret=1
 *   12    IO Protection Key    bus      WriteConfig=Never   IsSecret=1
 *   13    Reserved             --       WriteConfig=Never   IsSecret=0
 *   14    Reserved             --       WriteConfig=Never   IsSecret=0
 *   15    Device ID / serial   --       WriteConfig=Never   IsSecret=0
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

/* ---- Config zone template (Stage 1) ------------------------------------- */

/*
 * SlotConfig bit layout (2 bytes per slot, little-endian):
 *   Low byte  bits [3:0]  ReadKey
 *             bit  [4]    NoMac
 *             bit  [5]    LimitedUse
 *             bit  [6]    EncryptRead
 *             bit  [7]    IsSecret
 *   High byte bits [3:0]  WriteKey
 *             bits [7:4]  WriteConfig (0x0=Always, 0x2=Never, 0x3=Encrypt)
 *
 * KeyConfig bit layout (2 bytes per slot, little-endian):
 *   Low byte  bits [4:2]  KeyType (6=AES-128, 7=SHA/HMAC)
 *             bit  [5]    Lockable
 *   High byte bits [3:0]  AuthKey
 */

#define SLOTCFG_ROOTKEY_LO  0x80u   /* IsSecret=1 */
#define SLOTCFG_ROOTKEY_HI  0x20u   /* WriteConfig=Never */
#define SLOTCFG_SESSKEY_LO  0x80u   /* IsSecret=1 */
#define SLOTCFG_SESSKEY_HI  0x00u   /* WriteConfig=Always */
#define SLOTCFG_CUSTOM_LO   0x80u   /* IsSecret=1 */
#define SLOTCFG_CUSTOM_HI   0x00u   /* WriteConfig=Always */
#define SLOTCFG_IOPROT_LO   0x80u   /* IsSecret=1 */
#define SLOTCFG_IOPROT_HI   0x20u   /* WriteConfig=Never */
#define SLOTCFG_RESERVED_LO 0x00u
#define SLOTCFG_RESERVED_HI 0x20u   /* WriteConfig=Never */
#define SLOTCFG_DEVID_LO    0x00u
#define SLOTCFG_DEVID_HI    0x20u   /* WriteConfig=Never */
#define KEYCFG_AES_LO       0x38u   /* KeyType=6(AES), Lockable=1 */
#define KEYCFG_AES_HI       0x00u
#define KEYCFG_OTHER_LO     0x3Cu   /* KeyType=7(SHA), Lockable=1 */
#define KEYCFG_OTHER_HI     0x00u

static const uint8_t k_template_16_83[68] = {
	0xC0u, 0x00u, 0xAAu, 0x00u,		/* I2C_Addr, Reserved, OTPmode, ChipMode */
	SLOTCFG_ROOTKEY_LO,  SLOTCFG_ROOTKEY_HI,	/* Slot 0:  AppKey */
	SLOTCFG_ROOTKEY_LO,  SLOTCFG_ROOTKEY_HI,	/* Slot 1:  NwkKey */
	SLOTCFG_SESSKEY_LO,  SLOTCFG_SESSKEY_HI,	/* Slot 2:  NwkSKey/FNwkSIntKey */
	SLOTCFG_SESSKEY_LO,  SLOTCFG_SESSKEY_HI,	/* Slot 3:  SNwkSIntKey */
	SLOTCFG_SESSKEY_LO,  SLOTCFG_SESSKEY_HI,	/* Slot 4:  NwkSEncKey */
	SLOTCFG_SESSKEY_LO,  SLOTCFG_SESSKEY_HI,	/* Slot 5:  AppSKey */
	SLOTCFG_SESSKEY_LO,  SLOTCFG_SESSKEY_HI,	/* Slot 6:  JSIntKey */
	SLOTCFG_SESSKEY_LO,  SLOTCFG_SESSKEY_HI,	/* Slot 7:  JSEncKey */
	SLOTCFG_CUSTOM_LO,   SLOTCFG_CUSTOM_HI,	/* Slot 8:  Custom 1 */
	SLOTCFG_CUSTOM_LO,   SLOTCFG_CUSTOM_HI,	/* Slot 9:  Custom 2 */
	SLOTCFG_CUSTOM_LO,   SLOTCFG_CUSTOM_HI,	/* Slot 10: Custom 3 */
	SLOTCFG_CUSTOM_LO,   SLOTCFG_CUSTOM_HI,	/* Slot 11: Custom 4 */
	SLOTCFG_IOPROT_LO,   SLOTCFG_IOPROT_HI,	/* Slot 12: IO Prot Key */
	SLOTCFG_RESERVED_LO, SLOTCFG_RESERVED_HI,	/* Slot 13: Reserved */
	SLOTCFG_RESERVED_LO, SLOTCFG_RESERVED_HI,	/* Slot 14: Reserved */
	SLOTCFG_DEVID_LO,    SLOTCFG_DEVID_HI,	/* Slot 15: Device ID */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,  /* Counter[0] */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,  /* Counter[1] */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,  /* UseLock..KdfIvStr */
	0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
};

static const uint8_t k_template_88_91[4] = {
	0xFFu, 0xFFu,	/* SlotLocked: all unlocked */
	0x10u, 0x0Cu,	/* ChipOptions: AESEnable=1, IOProtKey=slot 12 */
};

static const uint8_t k_template_92_127[36] = {
	0x00u, 0x00u, 0x00u, 0x00u,			/* X509format */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[0]  AppKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[1]  NwkKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[2]  NwkSKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[3]  SNwkSIntKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[4]  NwkSEncKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[5]  AppSKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[6]  JSIntKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[7]  JSEncKey */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[8]  Custom 1 */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[9]  Custom 2 */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[10] Custom 3 */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[11] Custom 4 */
	KEYCFG_AES_LO,   KEYCFG_AES_HI,		/* KeyConfig[12] IO Prot Key */
	KEYCFG_OTHER_LO,  KEYCFG_OTHER_HI,		/* KeyConfig[13] Reserved */
	KEYCFG_OTHER_LO,  KEYCFG_OTHER_HI,		/* KeyConfig[14] Reserved */
	KEYCFG_OTHER_LO,  KEYCFG_OTHER_HI,		/* KeyConfig[15] Device ID */
};

/* ---- Utility helpers ----------------------------------------------------- */

static void printHex(uint8_t b)
	{
	if (b < 0x10)
		Serial.print('0');
	Serial.print(b, HEX);
	}

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

static void printKey(const uint8_t *key, uint8_t len)
	{
	for (uint8_t i = 0; i < len; ++i)
		{
		printHex(key[i]);
		if (i < len - 1)
			Serial.print(' ');
		}
	}

static bool waitForYes(void)
	{
	Serial.println(F("  Type YES and press Enter to proceed, or reset to abort:"));
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

static uint8_t readHexNibble(void)
	{
	while (true)
		{
		while (!Serial.available())
			;
		char c = (char)Serial.read();
		if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
		if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
		if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
		}
	}

static void readHexBytes(uint8_t *buf, uint8_t len)
	{
	for (uint8_t i = 0; i < len; ++i)
		{
		uint8_t hi = readHexNibble();
		uint8_t lo = readHexNibble();
		buf[i] = (uint8_t)((hi << 4) | lo);
		printHex(buf[i]);
		Serial.print(' ');
		}
	Serial.println();
	}

static bool readConfigZone(uint8_t cfg[128])
	{
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		return false;
	bool ok = atecc608c_read_config_zone(&dev, cfg);
	atecc608c_sleep(&dev);
	return ok;
	}

static bool getLockStatus(bool *cfg_locked, bool *data_locked)
	{
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		return false;
	bool ok1 = atecc608c_config_zone_is_locked(&dev, cfg_locked);
	bool ok2 = atecc608c_data_zone_is_locked(&dev, data_locked);
	atecc608c_sleep(&dev);
	return ok1 && ok2;
	}

/* ---- Stage 1: Config zone write and lock --------------------------------- */

static void run_stage1(void)
	{
	Serial.println(F("\n========================================"));
	Serial.println(F("Stage 1: Write and lock config zone"));
	Serial.println(F("========================================"));

	bool cfg_locked = false, data_locked = false;
	if (!getLockStatus(&cfg_locked, &data_locked))
		{
		Serial.println(F("ERROR: could not read lock status."));
		return;
		}
	if (cfg_locked)
		{
		Serial.println(F("Config zone is ALREADY LOCKED.  Stage 1 is complete."));
		return;
		}

	uint8_t cfg[128];
	if (!readConfigZone(cfg))
		{
		Serial.println(F("ERROR: failed to read config zone."));
		return;
		}
	Serial.println(F("\nCurrent config zone (before write):"));
	printHexDump(cfg, 128, 0);
	Serial.println();
	printSerialNumber(cfg);

	Serial.println(F("\nWriting config zone template..."));

	/* Region A: bytes 16..83 */
	for (uint8_t offset = 16u; offset < 84u; offset += 4u)
		{
		const uint8_t *word = &k_template_16_83[offset - 16u];
		uint8_t wake_resp[4];
		if (!atecc608c_wake(&dev, wake_resp) ||
		    !atecc608c_write_config_word(&dev, offset, word))
			{
			atecc608c_sleep(&dev);
			Serial.print(F("ERROR: write failed at byte "));
			Serial.println(offset);
			return;
			}
		atecc608c_sleep(&dev);
		Serial.print('.');
		}

	/* Region B: bytes 88..91 */
		{
		uint8_t wake_resp[4];
		if (!atecc608c_wake(&dev, wake_resp) ||
		    !atecc608c_write_config_word(&dev, 88u, k_template_88_91))
			{
			atecc608c_sleep(&dev);
			Serial.println(F("ERROR: write failed at byte 88"));
			return;
			}
		atecc608c_sleep(&dev);
		Serial.print('.');
		}

	/* Region C: bytes 92..127 */
	for (uint8_t offset = 92u; offset < 128u; offset += 4u)
		{
		const uint8_t *word = &k_template_92_127[offset - 92u];
		uint8_t wake_resp[4];
		if (!atecc608c_wake(&dev, wake_resp) ||
		    !atecc608c_write_config_word(&dev, offset, word))
			{
			atecc608c_sleep(&dev);
			Serial.print(F("ERROR: write failed at byte "));
			Serial.println(offset);
			return;
			}
		atecc608c_sleep(&dev);
		Serial.print('.');
		}
	Serial.println(F(" done."));

	/* Read back and verify */
	if (!readConfigZone(cfg))
		{
		Serial.println(F("ERROR: failed to read config zone after write."));
		return;
		}
	Serial.println(F("\nConfig zone after write:"));
	printHexDump(cfg, 128, 0);

	Serial.println(F("\nVerifying..."));
	bool ok = true;
	for (uint8_t i = 0; i < 68u; ++i)
		{
		if (cfg[16u + i] != k_template_16_83[i])
			{ ok = false; Serial.print(F("  MISMATCH byte ")); Serial.println(16u + i); }
		}
	for (uint8_t i = 0; i < 4u; ++i)
		{
		if (cfg[88u + i] != k_template_88_91[i])
			{ ok = false; Serial.print(F("  MISMATCH byte ")); Serial.println(88u + i); }
		}
	for (uint8_t i = 0; i < 36u; ++i)
		{
		if (cfg[92u + i] != k_template_92_127[i])
			{ ok = false; Serial.print(F("  MISMATCH byte ")); Serial.println(92u + i); }
		}
	if (!ok)
		{
		Serial.println(F("ERROR: verification failed.  Config zone NOT locked."));
		return;
		}
	Serial.println(F("  All bytes verified OK."));

	/* Lock */
	uint16_t summary_crc = atecc608c_crc16(cfg, 128u);
	Serial.print(F("\nConfig zone CRC-16: 0x"));
	printHex((uint8_t)(summary_crc >> 8));
	printHex((uint8_t)(summary_crc & 0xFF));
	Serial.println();

	Serial.println(F("\n*** POINT OF NO RETURN ***"));
	Serial.println(F("Locking the config zone is permanent and cannot be undone."));
	if (!waitForYes())
		return;

	Serial.println(F("\nSending Lock command..."));
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{ Serial.println(F("ERROR: wake failed.")); return; }
	bool locked = atecc608c_lock_config_zone(&dev, summary_crc);
	atecc608c_sleep(&dev);
	if (!locked)
		{ Serial.println(F("ERROR: Lock command failed.")); return; }

	/* Verify locked */
	if (!atecc608c_wake(&dev, wake_resp))
		{ Serial.println(F("ERROR: wake failed.")); return; }
	bool is_locked = false;
	atecc608c_config_zone_is_locked(&dev, &is_locked);
	atecc608c_sleep(&dev);
	if (!is_locked)
		{ Serial.println(F("ERROR: config zone still unlocked!")); return; }

	Serial.println(F("Config zone LOCKED successfully."));

	/* RNG test */
	Serial.println(F("\n--- Hardware RNG test ---"));
	uint8_t rnd1[32], rnd2[32];
	if (atecc608c_wake(&dev, wake_resp) &&
	    atecc608c_random_bytes(&dev, rnd1, 32))
		{
		atecc608c_sleep(&dev);
		Serial.print(F("  RNG[0]: "));
		for (uint8_t i = 0; i < 32; ++i) { printHex(rnd1[i]); Serial.print(' '); }
		Serial.println();
		}
	else
		{ atecc608c_sleep(&dev); }
	delay(5);
	if (atecc608c_wake(&dev, wake_resp) &&
	    atecc608c_random_bytes(&dev, rnd2, 32))
		{
		atecc608c_sleep(&dev);
		Serial.print(F("  RNG[1]: "));
		for (uint8_t i = 0; i < 32; ++i) { printHex(rnd2[i]); Serial.print(' '); }
		Serial.println();
		}
	else
		{ atecc608c_sleep(&dev); }
	if (memcmp(rnd1, rnd2, 32) != 0)
		Serial.println(F("  PASS -- outputs differ."));
	else
		Serial.println(F("  FAIL -- outputs identical!"));

	Serial.println(F("\nStage 1 complete.  Chip is ready for key injection (Stage 2)."));
	}

/* ---- Stage 2: Key injection --------------------------------------------- */

static bool write_key_to_slot(uint8_t slot, const uint8_t key[16])
	{
	uint8_t block[32];
	memcpy(block, key, 16u);
	memset(block + 16u, 0x00u, 16u);
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{ Serial.println(F("ERROR: wake failed.")); return false; }
	bool ok = atecc608c_write_data_slot(&dev, slot, block);
	atecc608c_sleep(&dev);
	if (!ok)
		{ Serial.print(F("ERROR: write failed for slot ")); Serial.println(slot); }
	return ok;
	}

static void run_stage2(void)
	{
	Serial.println(F("\n========================================"));
	Serial.println(F("Stage 2: Inject keys into data zone"));
	Serial.println(F("========================================"));

	bool cfg_locked = false, data_locked = false;
	if (!getLockStatus(&cfg_locked, &data_locked))
		{ Serial.println(F("ERROR: could not read lock status.")); return; }
	if (!cfg_locked)
		{
		Serial.println(F("ERROR: config zone is NOT locked.  Run Stage 1 first."));
		return;
		}
	if (data_locked)
		{
		Serial.println(F("ERROR: data zone is already locked.  Cannot inject keys."));
		return;
		}

	Serial.println(F("  Config zone: LOCKED"));
	Serial.println(F("  Data zone:   unlocked (plain writes allowed)"));
	Serial.println(F("\nWARNING: keys entered here are transmitted in plain text over Serial."));

	/* AppKey (required) */
	Serial.println(F("\n--- AppKey (slot 0) --- REQUIRED"));
	Serial.println(F("This is the LoRaWAN root key used for OTAA join."));
	Serial.println(F("Enter 32 hex characters (16 bytes), MSB first:"));
	Serial.print(F("  > "));

	uint8_t key[16];
	readHexBytes(key, 16u);
	Serial.println(F("  Writing to slot 0..."));
	if (!write_key_to_slot(0, key))
		{ memset(key, 0, 16); Serial.println(F("FATAL: AppKey injection failed.")); return; }
	memset(key, 0, sizeof(key));
	Serial.println(F("  PASS -- slot 0 accepted."));

	/* NwkKey (optional, LoRaWAN 1.1) */
	Serial.println(F("\n--- NwkKey (slot 1) --- OPTIONAL (LoRaWAN 1.1 only)"));
	Serial.println(F("This is the network root key, separate from AppKey in LoRaWAN 1.1."));
	Serial.println(F("Press Enter to skip, or enter 32 hex characters:"));
	Serial.print(F("  > "));
	while (!Serial.available()) ;
	if (Serial.peek() == '\n' || Serial.peek() == '\r')
		{
		Serial.read();
		Serial.println(F("  Skipped."));
		}
	else
		{
		readHexBytes(key, 16u);
		Serial.println(F("  Writing to slot 1..."));
		if (!write_key_to_slot(1, key))
			{ memset(key, 0, 16); Serial.println(F("FATAL: NwkKey injection failed.")); return; }
		memset(key, 0, sizeof(key));
		Serial.println(F("  PASS -- slot 1 accepted."));
		}

	/* IO Protection Key (optional) */
	Serial.println(F("\n--- IO Protection Key (slot 12) --- OPTIONAL"));
	Serial.println(F("This key encrypts I2C bus traffic to prevent sniffing."));
	Serial.println(F("Same value across all devices in a product line."));
	Serial.println(F("Press Enter to skip, or enter 32 hex characters:"));
	Serial.print(F("  > "));
	while (!Serial.available()) ;
	if (Serial.peek() == '\n' || Serial.peek() == '\r')
		{
		Serial.read();
		Serial.println(F("  Skipped."));
		}
	else
		{
		readHexBytes(key, 16u);
		Serial.println(F("  Writing to slot 12..."));
		if (!write_key_to_slot(12, key))
			{ memset(key, 0, 16); Serial.println(F("FATAL: IO Key injection failed.")); return; }
		memset(key, 0, sizeof(key));
		Serial.println(F("  PASS -- slot 12 accepted."));
		}

	Serial.println(F("\nStage 2 complete.  Chip is ready for data zone lock (Stage 3)."));
	Serial.println(F("IMPORTANT: Save the AppKey in your provisioning database NOW."));
	Serial.println(F("After Stage 3 it cannot be read back from the chip."));
	}

/* ---- Stage 3: Data zone lock --------------------------------------------- */

static void run_stage3(void)
	{
	Serial.println(F("\n========================================"));
	Serial.println(F("Stage 3: Lock data zone"));
	Serial.println(F("========================================"));

	bool cfg_locked = false, data_locked = false;
	if (!getLockStatus(&cfg_locked, &data_locked))
		{ Serial.println(F("ERROR: could not read lock status.")); return; }
	if (!cfg_locked)
		{ Serial.println(F("ERROR: config zone not locked.  Run Stage 1 first.")); return; }
	if (data_locked)
		{ Serial.println(F("Data zone is already locked.  Nothing to do.")); return; }

	uint8_t cfg[128];
	if (readConfigZone(cfg))
		{
		Serial.println();
		printSerialNumber(cfg);
		Serial.println(F("  Confirm this serial matches your factory record."));
		}

	Serial.println(F("\n*** POINT OF NO RETURN ***"));
	Serial.println(F("Locking the data zone is permanent and cannot be undone."));
	Serial.println(F("After locking:"));
	Serial.println(F("  - Root keys (slots 0, 1, 12) are sealed forever."));
	Serial.println(F("  - Session key slots (2-7) accept plain writes from firmware."));
	Serial.println(F("  - All secret slots (IsSecret=1) cannot be read back."));
	Serial.println(F("Ensure Stage 2 (key injection) is complete and keys are saved."));
	if (!waitForYes())
		return;

	Serial.println(F("\nSending Lock command (data+OTP zone)..."));
	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{ Serial.println(F("ERROR: wake failed.")); return; }
	bool locked = atecc608c_lock_data_zone(&dev);
	atecc608c_sleep(&dev);
	if (!locked)
		{ Serial.println(F("ERROR: lock failed.")); return; }

	/* Verify */
	if (!atecc608c_wake(&dev, wake_resp))
		{ Serial.println(F("ERROR: wake failed.")); return; }
	bool confirmed = false;
	atecc608c_data_zone_is_locked(&dev, &confirmed);
	atecc608c_sleep(&dev);
	if (!confirmed)
		{ Serial.println(F("ERROR: data zone still unlocked!")); return; }

	Serial.println(F("Data zone LOCKED successfully."));
	Serial.println(F("\nStage 3 complete.  Chip is fully provisioned and ready for deployment."));
	Serial.println(F("Register the device in TTN with the DevEUI and AppKey from Stage 2."));
	}

/* ---- Stage 4: Chip status ------------------------------------------------ */

static void run_status(void)
	{
	Serial.println(F("\n========================================"));
	Serial.println(F("Chip status"));
	Serial.println(F("========================================"));

	uint8_t cfg[128];
	if (!readConfigZone(cfg))
		{ Serial.println(F("ERROR: failed to read config zone.")); return; }

	Serial.println(F("\nConfig zone:"));
	printHexDump(cfg, 128, 0);
	Serial.println();
	printSerialNumber(cfg);

	bool cfg_locked = false, data_locked = false;
	if (getLockStatus(&cfg_locked, &data_locked))
		{
		Serial.print(F("  Config zone: "));
		Serial.println(cfg_locked ? F("LOCKED") : F("unlocked"));
		Serial.print(F("  Data zone:   "));
		Serial.println(data_locked ? F("LOCKED") : F("unlocked"));
		}

	/* RNG test */
	if (cfg_locked)
		{
		Serial.println(F("\n--- Hardware RNG test ---"));
		uint8_t rnd[32];
		uint8_t wake_resp[4];
		if (atecc608c_wake(&dev, wake_resp) &&
		    atecc608c_random_bytes(&dev, rnd, 32))
			{
			atecc608c_sleep(&dev);
			Serial.print(F("  RNG: "));
			for (uint8_t i = 0; i < 32; ++i) { printHex(rnd[i]); Serial.print(' '); }
			Serial.println();
			}
		else
			{
			atecc608c_sleep(&dev);
			Serial.println(F("  RNG: FAILED"));
			}
		}

	/* AES test if data zone is locked */
	if (data_locked)
		{
		Serial.println(F("\n--- AES engine test (slot 0) ---"));
		uint8_t zeros[16] = {0}, ct[16];
		uint8_t wake_resp[4];
		if (atecc608c_wake(&dev, wake_resp) &&
		    atecc608c_aes_ecb_encrypt(&dev, 0, zeros, ct))
			{
			atecc608c_sleep(&dev);
			Serial.print(F("  AES(slot0, 0^16) = "));
			for (int i = 0; i < 16; i++) { printHex(ct[i]); }
			Serial.println();
			Serial.println(F("  Compare this against AES-ECB(AppKey, 0^16) to verify the key."));
			}
		else
			{
			atecc608c_sleep(&dev);
			Serial.println(F("  AES: FAILED"));
			}
		}
	}

/* ---- Main menu ----------------------------------------------------------- */

static void showMenu(bool cfg_locked, bool data_locked)
	{
	Serial.println(F("\n========================================"));
	Serial.println(F("ATECC608C Provisioning Tool"));
	Serial.println(F("========================================"));
	Serial.println();
	Serial.print(F("  Config zone: "));
	Serial.println(cfg_locked ? F("LOCKED") : F("unlocked"));
	Serial.print(F("  Data zone:   "));
	Serial.println(data_locked ? F("LOCKED") : F("unlocked"));
	Serial.println();

	if (!cfg_locked)
		Serial.println(F("  [1] Write and lock config zone  (required first step)"));
	else
		Serial.println(F("  [1] Write and lock config zone  (already done)"));

	if (cfg_locked && !data_locked)
		Serial.println(F("  [2] Inject keys into data zone  (enter AppKey, NwkKey, etc.)"));
	else if (!cfg_locked)
		Serial.println(F("  [2] Inject keys into data zone  (requires Stage 1 first)"));
	else
		Serial.println(F("  [2] Inject keys into data zone  (already locked)"));

	if (cfg_locked && !data_locked)
		Serial.println(F("  [3] Lock data zone              (seals keys permanently)"));
	else if (!cfg_locked)
		Serial.println(F("  [3] Lock data zone              (requires Stages 1+2 first)"));
	else
		Serial.println(F("  [3] Lock data zone              (already done)"));

	Serial.println(F("  [4] Chip status                 (hex dump, serial, RNG/AES test)"));
	Serial.println();
	Serial.println(F("Enter choice [1-4]:"));
	Serial.print(F("  > "));
	}

void setup(void)
	{
	Serial.begin(115200);
	while (!Serial)
		;
	delay(100);

	Wire.begin();

	if (!atecc608c_init(&dev, &Wire, ATECC608C_ADDR,
	                    ATECC608C_RESET_PIN, ATECC608C_I2C_HZ))
		{
		Serial.println(F("\nFATAL: ATECC608C not found.  Check wiring and I2C address."));
		for (;;)
			;
		}
	}

void loop(void)
	{
	bool cfg_locked = false, data_locked = false;
	if (!getLockStatus(&cfg_locked, &data_locked))
		{
		Serial.println(F("ERROR: could not read lock status."));
		delay(3000);
		return;
		}

	showMenu(cfg_locked, data_locked);

	/* Wait for a menu choice */
	while (!Serial.available())
		;
	char choice = (char)Serial.read();
	/* Consume trailing newline */
	delay(50);
	while (Serial.available()) Serial.read();

	switch (choice)
		{
		case '1': run_stage1(); break;
		case '2': run_stage2(); break;
		case '3': run_stage3(); break;
		case '4': run_status(); break;
		default:
			Serial.println(F("Invalid choice."));
			break;
		}
	}
