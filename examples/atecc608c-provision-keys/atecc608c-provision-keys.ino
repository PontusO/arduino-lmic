/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C Stage 2 provisioning sketch -- key injection.
 *
 * PURPOSE
 * -------
 * Writes LoRaWAN keys into the ATECC608C data zone BEFORE the data zone is
 * locked.  Before the data zone is locked all slots accept plain (unencrypted)
 * Write commands regardless of the access policies set in the config zone.
 *
 * KEYS INJECTED
 * -------------
 *   Slot 0  AppKey    16-byte AES-128 root key for OTAA join.
 *                     Per-device, unique to each chip.
 *   Slot 3  AuthKey   16-byte HMAC key used to authenticate encrypted writes
 *                     to slots 1 and 2 after the data zone is locked (Stage 3).
 *                     Same value can be shared across all chips at a site, or
 *                     be per-device -- operator's choice.
 *
 * OPTIONAL (ABP or pre-provisioned OTAA):
 *   Slot 1  NwkSKey   16-byte network session key.
 *   Slot 2  AppSKey   16-byte application session key.
 *   These can be injected with this sketch if the device will use ABP, or left
 *   empty (zeros) if OTAA is used (the LMIC stack writes them after join).
 *
 * WRITE FORMAT
 * ------------
 * Each data zone slot Write command transfers 32 bytes (one 32-byte block).
 * For 16-byte AES/HMAC key slots the key occupies bytes 0..15; bytes 16..31
 * of the written block must be zero.  The chip ignores bytes 16..31 for
 * AES-typed slots (KeyType=6) and for HMAC-typed slots (KeyType=7).
 *
 * VERIFICATION
 * ------------
 * The ATECC608C does not permit Read commands on data zone slots before the
 * data zone is locked.  Verification relies on the Write command's status
 * response: status 0x00 means the chip accepted and stored the data.  The
 * command and response frames are both CRC-validated, so a silent corruption
 * during transfer would be caught by the protocol layer.
 *
 * After the data zone is locked (Stage 3) you can verify the AppKey indirectly
 * using the ATECC608C MAC or CheckMAC command.
 *
 * PREREQUISITES
 * -------------
 *   - Stage 1 (config zone write + lock) must already have been completed.
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

/* ---- Utility helpers ----------------------------------------------------- */

static void printHex(uint8_t b)
	{
	if (b < 0x10)
		Serial.print('0');
	Serial.print(b, HEX);
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
 * Read exactly one hex nibble from Serial.  Blocks until a valid hex character
 * arrives; ignores spaces, newlines, and carriage returns.
 * Returns 0..15.
 */
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
		/* ignore spaces, CR, LF, and other non-hex characters */
		}
	}

/*
 * Read exactly `len` bytes of hex input from Serial into buf[].
 * The user must type exactly 2*len hex characters (case-insensitive).
 * Non-hex characters (spaces, newlines) are silently skipped.
 * Echoes each byte back to Serial as it is parsed.
 */
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

/*
 * Block until the user types "YES" (case-sensitive) followed by Enter.
 */
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

/* ---- Key injection helpers ----------------------------------------------- */

/*
 * Write a 16-byte key into a data zone slot.
 *
 * The Write command transfers 32 bytes; the key occupies bytes 0..15 and
 * bytes 16..31 are padded with zeros (the chip ignores them for AES/HMAC
 * key slots).
 *
 * Wakes the chip, writes, then sleeps.  Returns true on success.
 */
static bool write_key_to_slot(uint8_t slot, const uint8_t key[16])
	{
	uint8_t block[32];
	memcpy(block, key, 16u);
	memset(block + 16u, 0x00u, 16u);

	uint8_t wake_resp[4];
	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: wake failed before write."));
		return false;
		}

	bool ok = atecc608c_write_data_slot(&dev, slot, block);
	atecc608c_sleep(&dev);

	if (!ok)
		{
		Serial.print(F("ERROR: write failed for slot "));
		Serial.println(slot);
		}
	return ok;
	}

/*
 * Inject one key: prompt, read hex input, write.
 *
 * NOTE: The ATECC608C does not permit plain Read commands on data zone slots
 * before the data zone is locked.  Verification relies on the Write command's
 * own status response (0x00 = chip accepted and stored the data).  Both the
 * outgoing command and the incoming response are CRC-validated by the protocol
 * layer, so silent transfer corruption is caught here.
 *
 * Returns true on success.
 */
static bool inject_key(uint8_t slot, const __FlashStringHelper *name)
	{
	Serial.println();
	Serial.print(F("--- "));
	Serial.print(name);
	Serial.print(F(" (slot "));
	Serial.print(slot);
	Serial.println(F(") ---"));
	Serial.println(F("Enter 32 hex characters (16 bytes).  Example: AABBCCDDEEFF00112233445566778899"));
	Serial.print(F("  > "));

	uint8_t key[16];
	readHexBytes(key, 16u);

	Serial.print(F("  Writing to slot "));
	Serial.print(slot);
	Serial.println(F("..."));

	bool ok = write_key_to_slot(slot, key);

	/* Securely erase the key from RAM before returning. */
	memset(key, 0, sizeof(key));

	if (!ok)
		return false;

	Serial.print(F("  PASS -- slot "));
	Serial.print(slot);
	Serial.println(F(" write accepted (status 0x00)."));
	return true;
	}

/* ---- Arduino entry points ------------------------------------------------- */

void setup(void)
	{
	Serial.begin(115200);
	while (!Serial)
		;
	delay(100);

	Serial.println(F("ATECC608C Key Injection"));
	Serial.println(F("======================="));
	Serial.println(F("Stage 2: Inject keys into the data zone (before data zone lock)."));

	Wire.begin();

	if (!atecc608c_init(&dev, &Wire, ATECC608C_ADDR,
	                    ATECC608C_RESET_PIN, ATECC608C_I2C_HZ))
		{
		Serial.println(F("\nERROR: chip not found.  Check wiring and I2C address."));
		for (;;)
			;
		}

	Serial.println(F("\nChip detected and awake."));

	/* --- Preflight checks ------------------------------------------------- */

	uint8_t wake_resp[4];

	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: wake failed."));
		for (;;)
			;
		}

	bool cfg_locked = false;
	bool data_locked = false;
	bool ok_cfg  = atecc608c_config_zone_is_locked(&dev, &cfg_locked);
	bool ok_data = atecc608c_data_zone_is_locked(&dev, &data_locked);
	atecc608c_sleep(&dev);

	if (!ok_cfg || !ok_data)
		{
		Serial.println(F("ERROR: could not read lock status."));
		for (;;)
			;
		}

	if (!cfg_locked)
		{
		Serial.println(F("ERROR: config zone is NOT locked."));
		Serial.println(F("  Run the atecc608c-provision sketch (Stage 1) first."));
		for (;;)
			;
		}

	if (data_locked)
		{
		Serial.println(F("ERROR: data zone is already locked."));
		Serial.println(F("  Key injection must be done BEFORE the data zone is locked."));
		Serial.println(F("  Plain writes are rejected on locked data zones."));
		for (;;)
			;
		}

	Serial.println(F("  Config zone: LOCKED (good)"));
	Serial.println(F("  Data zone:   unlocked (plain writes allowed)"));

	/*
	 * Note: the ATECC608C rejects plain Read commands on data zone slots
	 * before the data zone is locked.  We cannot display current slot
	 * contents at this stage.
	 */

	/* --- Key injection ---------------------------------------------------- */

	Serial.println(F("\nReady to inject keys."));
	Serial.println(F("WARNING: keys entered here are transmitted in plain text over Serial."));
	Serial.println(F("Ensure no one can sniff the serial port during this operation."));

	if (!inject_key(0, F("AppKey")))
		{
		Serial.println(F("\nFATAL: AppKey injection failed."));
		for (;;)
			;
		}

	if (!inject_key(3, F("AuthKey")))
		{
		Serial.println(F("\nFATAL: AuthKey injection failed."));
		for (;;)
			;
		}

	Serial.println(F("\n======================="));
	Serial.println(F("Key injection complete."));
	Serial.println(F("The chip is now ready for Stage 3 (data zone lock)."));
	Serial.println(F("After Stage 3 the keys cannot be read back in plain text."));
	}

void loop(void)
	{
	/* nothing */
	}
