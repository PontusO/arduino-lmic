/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C LMIC secure element driver -- public API.
 *
 * Adapts the atecc608c_backend crypto layer to the LMIC SE driver interface
 * defined in lmic_secure_element_interface.h.  Include this header (or simply
 * include <lmic.h>) to access the driver functions and the
 * LMIC_SecureElement_Atecc608c_configure() hardware-RNG registration call.
 *
 *******************************************************************************/

#ifndef _lmic_secure_element_atecc608c_h_
#define _lmic_secure_element_atecc608c_h_

#ifndef _lmic_secure_element_interface_h_
# include "../../i/lmic_secure_element_interface.h"
#endif

#include <stdbool.h>
LMIC_BEGIN_DECLS

LMIC_SecureElement_DECLARE_DRIVER_FNS(Atecc608c);

/*
 * Wire the ATECC608C hardware device and optional hardware RNG into the SE
 * backend.  Call this once during setup, after atecc608c_init(), before
 * LMIC_reset().
 *
 * chip_dev     Pointer to the initialised atecc608c_t device, passed as
 *              void * to avoid Wire.h in C callers.  The backend uses this
 *              to perform AppKey operations (join MIC, join accept decrypt,
 *              session key derivation) via the chip's on-board AES engine.
 *              The AppKey never touches host RAM.
 *
 * hw_random_fn Function that fills out[0..len-1] with up to 32 hardware
 *              random bytes.  Pass NULL to use the built-in software PRNG.
 *
 * hw_ctx       Opaque pointer forwarded to hw_random_fn on each call
 *              (typically the same atecc608c_t * cast to void *).
 *
 * Example sketch usage:
 *   static atecc608c_t g_chip;
 *
 *   static bool hw_rng(uint8_t *out, uint8_t len, void *ctx) {
 *       atecc608c_t *dev = (atecc608c_t *)ctx;
 *       uint8_t wr[4];
 *       if (!atecc608c_wake(dev, wr)) return false;
 *       bool ok = atecc608c_random_bytes(dev, out, len);
 *       atecc608c_sleep(dev);
 *       return ok;
 *   }
 *
 *   void setup() {
 *       atecc608c_init(&g_chip, &Wire, 0x60, -1, 100000UL);
 *       LMIC_SecureElement_Atecc608c_configure(&g_chip, hw_rng, &g_chip);
 *       LMIC_reset();
 *   }
 */
LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_configure(
	void *chip_dev,
	bool (*hw_random_fn)(uint8_t *out, uint8_t len, void *ctx),
	void *hw_ctx);

LMIC_END_DECLS

#endif