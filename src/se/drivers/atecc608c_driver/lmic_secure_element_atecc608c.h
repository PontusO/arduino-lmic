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
 * Wire a hardware RNG into the ATECC608C secure element backend.
 *
 * Call this once during setup, after the hardware device has been initialised
 * with atecc608c_init(), to replace the built-in software PRNG with the chip's
 * true random number generator.
 *
 * hw_random_fn -- function that fills out[0..len-1] with random bytes, where
 *                 len is always in [1, 32].  Returns true on success.
 * hw_ctx       -- opaque pointer passed to hw_random_fn (typically a pointer
 *                 to the atecc608c_t device handle).
 *
 * Passing NULL for hw_random_fn reverts to the built-in software PRNG.
 *
 * Example sketch usage:
 *   static atecc608c_t g_hw_dev;
 *
 *   static bool my_hw_random(uint8_t *out, uint8_t len, void *ctx) {
 *       return atecc608c_random_bytes((atecc608c_t *)ctx, out, len);
 *   }
 *
 *   void setup() {
 *       atecc608c_init(&g_hw_dev, &Wire, 0x60, -1, 100000);
 *       LMIC_SecureElement_Atecc608c_configure(my_hw_random, &g_hw_dev);
 *       LMIC_reset();
 *   }
 */
LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_configure(
	bool (*hw_random_fn)(uint8_t *out, uint8_t len, void *ctx),
	void *hw_ctx);

LMIC_END_DECLS

#endif