/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * Layer 4 integration test: OTAA join and uplink using the ATECC608C
 * secure element driver.
 *
 * This sketch performs a complete LoRaWAN OTAA join via The Things Network
 * (or any compatible network server) and then transmits a "Hello, world!"
 * payload on a 60-second interval.  The ATECC608C chip is used as the
 * secure element backend, which means:
 *
 *   - All join-request and uplink MIC / encryption operations are performed
 *     by the atecc608c_backend crypto layer using LMIC's AES engine.
 *   - All random numbers (used for DevNonce generation etc.) are drawn from
 *     the ATECC608C hardware True RNG via the atecc608c_random_bytes()
 *     command.
 *   - Keys are held in the backend context in RAM (same as the default SE);
 *     the ATECC608C is used for its hardware RNG only in this driver revision.
 *
 * Prerequisites:
 *   - ATECC608C wired to the default I2C bus at address 0x60.
 *   - LoRa radio module wired and pin map filled in below.
 *   - lmic_project_config.h must select the correct region and radio.
 *   - lmic_project_config.h must define:
 *       #define LMIC_SECURE_ELEMENT  Atecc608c
 *     to activate this driver instead of the default software SE.
 *
 * Credential configuration:
 *   Replace the FILLMEIN placeholders with values from your network console.
 *   AppEUI and DevEUI must be in little-endian (LSB first) byte order.
 *   AppKey is in big-endian (MSB first) byte order.
 *
 * Do not forget to define the radio type correctly in
 * arduino-lmic/project_config/lmic_project_config.h or from your BOARDS.txt.
 *
 *******************************************************************************/

#include <lmic.h>
#include <hal/hal.h>
#include <SPI.h>
#include <Wire.h>

//
// For normal use, we require that you edit the sketch to replace FILLMEIN
// with values assigned by your network console.  However, for regression
// tests we want to be able to compile these scripts.  The regression tests
// define COMPILE_REGRESSION_TEST, and in that case we define FILLMEIN to a
// non-working but innocuous value.
//
#ifdef COMPILE_REGRESSION_TEST
# define FILLMEIN 0
#else
# warning "You must replace the values marked FILLMEIN with real values from your network console!"
# define FILLMEIN (#dont edit this, edit the lines that use FILLMEIN)
#endif

// This EUI must be in little-endian format, so least-significant-byte
// first. When copying an EUI from ttnctl output, this means to reverse
// the bytes. For TTN issued EUIs the last bytes should be 0xD5, 0xB3, 0x70.
static const u1_t PROGMEM APPEUI[8] = { FILLMEIN };

// This should also be in little-endian format, see above.
static const u1_t PROGMEM DEVEUI[8] = { FILLMEIN };

// This key should be in big-endian format (or, since it is not really a
// number but a block of memory, endianness does not really apply). In
// practice, a key taken from ttnctl can be copied as-is.
static const u1_t PROGMEM APPKEY[16] = { FILLMEIN };

// LMIC credential callbacks -- called from LMIC_reset() to push credentials
// into the active secure element.
void os_getArtEui(u1_t *buf) { memcpy_P(buf, APPEUI, 8); }
void os_getDevEui(u1_t *buf) { memcpy_P(buf, DEVEUI, 8); }
void os_getDevKey(u1_t *buf) { memcpy_P(buf, APPKEY, 16); }

/* ---- ATECC608C configuration --------------------------------------------- */

#define ATECC608C_ADDR        0x60
#define ATECC608C_RESET_PIN   (-1)   /* -1 = not connected */
#define ATECC608C_I2C_HZ      100000UL

static atecc608c_t g_hw_dev;

/*
 * Hardware RNG trampoline.
 *
 * Called by the SE backend whenever the LMIC stack needs random bytes (e.g.
 * for DevNonce generation).  Wakes the ATECC608C, draws up to 32 bytes from
 * the hardware True RNG, then puts the chip back to sleep.
 *
 * len is always in [1, 32] because the backend chunks larger requests.
 */
static bool atecc608c_hw_random(uint8_t *out, uint8_t len, void *ctx)
	{
	atecc608c_t *dev = (atecc608c_t *)ctx;
	uint8_t wake_resp[4];

	if (!atecc608c_wake(dev, wake_resp))
		return false;

	bool ok = atecc608c_random_bytes(dev, out, len);
	atecc608c_sleep(dev);
	return ok;
	}

/* ---- Radio pin mapping ---------------------------------------------------- */

//
// For many standard boards there are pre-built pin maps in getpinmap_*.cpp.
// Replace the entries below with the correct values for your hardware.
// See https://github.com/mcci-catena/arduino-lmic for board-specific examples.
//
const lmic_pinmap lmic_pins = {
	.nss  = FILLMEIN,
	.rxtx = LMIC_UNUSED_PIN,
	.rst  = FILLMEIN,
	.dio  = { FILLMEIN, FILLMEIN, LMIC_UNUSED_PIN },
};

/* ---- Application logic --------------------------------------------------- */

static uint8_t mydata[] = "Hello, world!";
static osjob_t sendjob;

// Schedule TX every this many seconds (may be longer due to duty-cycle limits).
const unsigned TX_INTERVAL = 60;

static void printHex2(unsigned v)
	{
	v &= 0xff;
	if (v < 16)
		Serial.print('0');
	Serial.print(v, HEX);
	}

void onEvent(ev_t ev)
	{
	Serial.print(os_getTime());
	Serial.print(F(": "));
	switch (ev)
		{
		case EV_SCAN_TIMEOUT:
			Serial.println(F("EV_SCAN_TIMEOUT"));
			break;
		case EV_BEACON_FOUND:
			Serial.println(F("EV_BEACON_FOUND"));
			break;
		case EV_BEACON_MISSED:
			Serial.println(F("EV_BEACON_MISSED"));
			break;
		case EV_BEACON_TRACKED:
			Serial.println(F("EV_BEACON_TRACKED"));
			break;
		case EV_JOINING:
			Serial.println(F("EV_JOINING"));
			break;
		case EV_JOINED:
			Serial.println(F("EV_JOINED"));
			{
			u4_t netid   = 0;
			devaddr_t devaddr = 0;
			u1_t nwkKey[16];
			u1_t artKey[16];
			LMIC_getSessionKeys(&netid, &devaddr, nwkKey, artKey);
			Serial.print(F("  netid:   "));
			Serial.println(netid, DEC);
			Serial.print(F("  devaddr: "));
			Serial.println(devaddr, HEX);
			Serial.print(F("  AppSKey: "));
			for (size_t i = 0; i < sizeof(artKey); ++i)
				{
				if (i != 0)
					Serial.print('-');
				printHex2(artKey[i]);
				}
			Serial.println();
			Serial.print(F("  NwkSKey: "));
			for (size_t i = 0; i < sizeof(nwkKey); ++i)
				{
				if (i != 0)
					Serial.print('-');
				printHex2(nwkKey[i]);
				}
			Serial.println();
			}
			// Disable link check validation (automatically enabled during join,
			// but slow data rates change max TX size).
			LMIC_setLinkCheckMode(0);
			break;
		case EV_JOIN_FAILED:
			Serial.println(F("EV_JOIN_FAILED"));
			break;
		case EV_REJOIN_FAILED:
			Serial.println(F("EV_REJOIN_FAILED"));
			break;
		case EV_TXCOMPLETE:
			Serial.println(F("EV_TXCOMPLETE (includes waiting for RX windows)"));
			if (LMIC.txrxFlags & TXRX_ACK)
				Serial.println(F("  Received ack"));
			if (LMIC.dataLen)
				{
				Serial.print(F("  Received "));
				Serial.print(LMIC.dataLen);
				Serial.println(F(" bytes of payload"));
				}
			os_setTimedCallback(&sendjob,
			                    os_getTime() + sec2osticks(TX_INTERVAL),
			                    do_send);
			break;
		case EV_LOST_TSYNC:
			Serial.println(F("EV_LOST_TSYNC"));
			break;
		case EV_RESET:
			Serial.println(F("EV_RESET"));
			break;
		case EV_RXCOMPLETE:
			Serial.println(F("EV_RXCOMPLETE"));
			break;
		case EV_LINK_DEAD:
			Serial.println(F("EV_LINK_DEAD"));
			break;
		case EV_LINK_ALIVE:
			Serial.println(F("EV_LINK_ALIVE"));
			break;
		case EV_TXSTART:
			Serial.println(F("EV_TXSTART"));
			break;
		case EV_TXCANCELED:
			Serial.println(F("EV_TXCANCELED"));
			break;
		case EV_RXSTART:
			/* do not print anything -- it wrecks timing */
			break;
		case EV_JOIN_TXCOMPLETE:
			Serial.println(F("EV_JOIN_TXCOMPLETE: no JoinAccept"));
			break;
		default:
			Serial.print(F("Unknown event: "));
			Serial.println((unsigned)ev);
			break;
		}
	}

void do_send(osjob_t *j)
	{
	if (LMIC.opmode & OP_TXRXPEND)
		{
		Serial.println(F("OP_TXRXPEND, not sending"));
		}
	else
		{
		LMIC_setTxData2(1, mydata, sizeof(mydata) - 1, 0);
		Serial.println(F("Packet queued"));
		}
	// Next TX is scheduled after EV_TXCOMPLETE.
	}

void setup()
	{
	Serial.begin(9600);
	Serial.println(F("Starting ATECC608C OTAA example"));

	#ifdef VCC_ENABLE
	// For Pinoccio Scout boards
	pinMode(VCC_ENABLE, OUTPUT);
	digitalWrite(VCC_ENABLE, HIGH);
	delay(1000);
	#endif

	// Initialise the ATECC608C hardware device.
	if (!atecc608c_init(&g_hw_dev, &Wire, ATECC608C_ADDR,
	                    ATECC608C_RESET_PIN, ATECC608C_I2C_HZ))
		{
		Serial.println(F("ATECC608C init FAILED -- check wiring"));
		// Continue anyway; the software PRNG fallback will be used.
		}
	else
		{
		/*
		 * Verify the chip is alive before handing it to the SE backend.
		 * This also confirms the I2C address and bus speed are correct.
		 */
		uint8_t wake_resp[4];
		if (atecc608c_wake(&g_hw_dev, wake_resp))
			{
			atecc608c_sleep(&g_hw_dev);
			Serial.println(F("ATECC608C OK"));
			}
		else
			{
			Serial.println(F("ATECC608C wake FAILED -- using software PRNG"));
			}

		/*
		 * Register the hardware RNG with the SE backend.
		 * This must be called before LMIC_reset() so that any random
		 * numbers generated during initialisation use the hardware source.
		 */
		LMIC_SecureElement_Atecc608c_configure(atecc608c_hw_random, &g_hw_dev);
		}

	// LMIC init.  LMIC_reset() calls LMIC_SecureElement_initialize() and
	// then pushes the credentials from os_getDevKey / os_getArtEui /
	// os_getDevEui into the active secure element backend.
	os_init();
	LMIC_reset();

	// Start the join process (OTAA).
	do_send(&sendjob);
	}

void loop()
	{
	os_runloop_once();
	}
