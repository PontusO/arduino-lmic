/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C OTAA example -- hardware-secured LoRaWAN join and uplink.
 *
 * This sketch performs a complete LoRaWAN OTAA join via The Things Network
 * (or any compatible network server) and then transmits a "Hello, world!"
 * payload on a 60-second interval.  All cryptographic keys are managed by
 * the ATECC608C secure element:
 *
 *   - AppKey is sealed in chip slot 0 (never touches host RAM).
 *   - Join request MIC and join accept decryption use the chip's on-board
 *     AES-128 engine via slot 0.
 *   - Session keys (NwkSKey, AppSKey) are derived via chip AES, written
 *     to chip slots 2 and 5, then scrubbed from RAM.
 *   - All data-frame MIC and payload encryption use the chip's AES engine
 *     with the session key slots.  No key material persists in host RAM.
 *   - Random numbers (DevNonce etc.) are drawn from the ATECC608C hardware
 *     True RNG.
 *
 * Chip provisioning:
 *   The ATECC608C must be provisioned before this sketch will work:
 *     Stage 1: atecc608c-provision      (config zone layout and lock)
 *     Stage 2: atecc608c-provision-keys  (AppKey injection)
 *     Stage 3: atecc608c-provision-lock-data (data zone lock)
 *
 * Prerequisites:
 *   - ATECC608C wired to the default I2C bus at address 0x60.
 *   - LoRa radio module wired and pin map filled in below.
 *   - lmic_project_config.h must select the correct region and radio.
 *   - lmic_project_config.h must define:
 *       #define LMIC_CFG_SecureElement_DRIVER  Atecc608c
 *     to activate this driver instead of the default software SE.
 *
 * Credential configuration:
 *   Replace the FILLMEIN placeholders with values from your network console.
 *   AppEUI and DevEUI must be in little-endian (LSB first) byte order.
 *   AppKey is NOT provided here -- it is sealed in the ATECC608C and used
 *   directly by the chip without ever exposing the key to the host CPU.
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

// LMIC credential callbacks -- called from LMIC_reset() to push credentials
// into the active secure element.
void os_getArtEui(u1_t *buf) { memcpy_P(buf, APPEUI, 8); }
void os_getDevEui(u1_t *buf) { memcpy_P(buf, DEVEUI, 8); }
// AppKey is sealed in ATECC608C slot 0 -- the backend ignores these bytes.
void os_getDevKey(u1_t *buf) { memset(buf, 0, 16); }

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
			Serial.print(F("  netid:   "));
			Serial.println(LMIC.netid, DEC);
			Serial.print(F("  devaddr: "));
			Serial.println(LMIC.devaddr, HEX);
			Serial.println(F("  Session keys sealed on ATECC608C (slots 2/5)"));
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
		 * Register the chip and hardware RNG with the SE backend.
		 * This must be called before LMIC_reset() so that the backend
		 * has the chip pointer for AppKey crypto and hardware RNG.
		 */
		LMIC_SecureElement_Atecc608c_configure(&g_hw_dev, atecc608c_hw_random, &g_hw_dev);
		}

	// LMIC init.  LMIC_reset() reinitialises the SE backend (preserving
	// the chip pointer and RNG hook set by configure() above).
	os_init();
	LMIC_reset();

	// Start the join process (OTAA).
	do_send(&sendjob);
	}

void loop()
	{
	os_runloop_once();
	}
