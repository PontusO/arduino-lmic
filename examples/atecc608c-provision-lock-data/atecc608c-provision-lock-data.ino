/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C Stage 3 provisioning sketch -- data zone lock.
 *
 * PURPOSE
 * -------
 * Permanently locks the ATECC608C data+OTP zone, activating all slot access
 * policies that were encoded in the configuration zone during Stage 1:
 *
 *   Slot 0  AppKey    WriteConfig=Never  -- sealed forever; no read or write.
 *   Slot 1  NwkSKey   WriteConfig=Encrypt -- only writable via authenticated
 *   Slot 2  AppSKey   WriteConfig=Encrypt    encrypted write using slot 3.
 *   Slot 3  AuthKey   WriteConfig=Never  -- sealed forever; no read or write.
 *   4-15    Reserved  WriteConfig=Never  -- permanently empty.
 *
 * PREREQUISITES
 * -------------
 *   - Stage 1 (config zone lock) complete.
 *   - Stage 2 (key injection) complete and keys saved to secure storage.
 *   - ATECC608C wired to the default I2C bus at address 0x60.
 *   - Serial monitor open at 115200 baud.
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
	}

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

/* ---- Arduino entry points ------------------------------------------------- */

void setup(void)
	{
	Serial.begin(115200);
	while (!Serial)
		;
	delay(100);

	Serial.println(F("ATECC608C Data Zone Lock"));
	Serial.println(F("========================"));
	Serial.println(F("Stage 3: Permanently lock the data zone."));

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

	bool cfg_locked  = false;
	bool data_locked = false;
	bool ok_cfg  = atecc608c_config_zone_is_locked(&dev, &cfg_locked);
	bool ok_data = atecc608c_data_zone_is_locked(&dev, &data_locked);

	/* Read serial number while awake. */
	uint8_t cfg[128];
	bool ok_read = atecc608c_read_config_zone(&dev, cfg);

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
		Serial.println(F("  Run atecc608c-provision (Stage 1) first."));
		for (;;)
			;
		}

	if (data_locked)
		{
		Serial.println(F("Data zone is already locked.  Nothing to do."));
		Serial.println(F("  AppKey and AuthKey are sealed."));
		Serial.println(F("  The chip is ready for deployment."));
		for (;;)
			;
		}

	Serial.println(F("  Config zone: LOCKED"));
	Serial.println(F("  Data zone:   unlocked -- will be locked now"));

	if (ok_read)
		{
		Serial.println();
		printSerialNumber(cfg);
		Serial.println(F("  Confirm this serial number matches your factory record"));
		Serial.println(F("  before proceeding."));
		}

	/* --- Confirmation ----------------------------------------------------- */

	Serial.println(F("\n*** POINT OF NO RETURN ***"));
	Serial.println(F("Locking the data zone is permanent and cannot be undone."));
	Serial.println(F("After locking:"));
	Serial.println(F("  - AppKey (slot 0) and AuthKey (slot 3) are sealed forever."));
	Serial.println(F("  - NwkSKey/AppSKey (slots 1/2) require encrypted write to update."));
	Serial.println(F("  - No slot can be read in plain text."));
	Serial.println(F("Ensure Stage 2 (key injection) is complete and keys are saved."));

	if (!waitForYes())
		return;

	/* --- Lock ------------------------------------------------------------- */

	Serial.println(F("\nSending Lock command (data+OTP zone)..."));

	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: wake failed before lock."));
		for (;;)
			;
		}

	bool locked = atecc608c_lock_data_zone(&dev);
	atecc608c_sleep(&dev);

	if (!locked)
		{
		Serial.print(F("ERROR: lock failed.  Status byte: 0x"));
		printHex(atecc608c_last_lock_status);
		Serial.println();
		for (;;)
			;
		}

	Serial.println(F("Lock command accepted."));

	/* --- Verify ----------------------------------------------------------- */

	if (!atecc608c_wake(&dev, wake_resp))
		{
		Serial.println(F("ERROR: wake failed during verification."));
		for (;;)
			;
		}

	bool confirmed = false;
	bool ok_verify = atecc608c_data_zone_is_locked(&dev, &confirmed);
	atecc608c_sleep(&dev);

	if (!ok_verify || !confirmed)
		{
		Serial.println(F("ERROR: data zone reports as unlocked after lock command!"));
		for (;;)
			;
		}

	/* --- Done ------------------------------------------------------------- */

	Serial.println(F("Data zone confirmed LOCKED."));
	Serial.println(F("\n========================"));
	Serial.println(F("Provisioning complete."));
	Serial.println(F("The chip is ready for deployment."));
	Serial.println(F("AppKey is sealed -- OTAA join will work once the device"));
	Serial.println(F("is registered in TTN with this DevEUI and AppKey."));
	}

void loop(void)
	{
	/* nothing */
	}
