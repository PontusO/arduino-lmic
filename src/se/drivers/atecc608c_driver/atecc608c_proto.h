/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C protocol layer -- command framing, wake/sleep/idle, RNG, CRC-16.
 *
 * Sits above the HAL and below the crypto backend.  Provides the public API
 * used directly by application sketches that need raw chip access (e.g. the
 * atecc608c-probe example).
 *
 *******************************************************************************/

#ifndef ATECC608C_PROTO_H
#define ATECC608C_PROTO_H

#include "atecc608c_hal.h"

struct atecc608c_t {
    atecc608c_hal_t hal;
    bool initialized;
};

#ifdef __cplusplus
extern "C" {
#endif

bool atecc608c_wake(atecc608c_t *dev, uint8_t wake_resp[4]);
bool atecc608c_init(atecc608c_t *dev,
                      TwoWire *wire,
                      uint8_t i2c_addr_7bit,
                      int8_t reset_pin,
                      uint32_t i2c_clock_hz);

bool atecc608c_reset_and_probe(atecc608c_t *dev);
bool atecc608c_ping(atecc608c_t *dev);

/*
 * Raw transaction placeholder.
 * You will replace this once you have the exact ATECC608C command frame format
 * wired in from the command-set documentation / middleware.
 */
bool atecc608c_raw_exchange(atecc608c_t *dev,
                              const uint8_t *tx,
                              size_t tx_len,
                              uint8_t *rx,
                              size_t rx_len);

/*
 * Placeholder for first real command.
 * Currently just a transport stub, not a real ATEC608C Generate Random command.
 */
bool atecc608c_generate_random_stub(atecc608c_t *dev,
                                      uint8_t *out,
                                      size_t out_len);

/*
 * CRC-16/IBM (polynomial 0x8005, init 0, LSB-first per bit, little-endian output).
 * Used to frame and validate ATECC608C command/response packets.
 */
uint16_t atecc608c_crc16(const uint8_t *data, size_t len);

/*
 * Send a Sleep word-address byte (0x01) to put the chip into sleep mode.
 * Chip loses state; requires a full wake sequence before next command.
 */
bool atecc608c_sleep(atecc608c_t *dev);

/*
 * Send an Idle word-address byte (0x02) to put the chip into idle mode.
 * Chip retains volatile state and can resume faster than from sleep.
 */
bool atecc608c_idle(atecc608c_t *dev);

/*
 * Issue the ATECC608C Random command (opcode 0x1B) and return up to 32 hardware-
 * generated random bytes in out[0..len-1].  len must be in [1, 32].
 * The chip must be awake before this call; it is left awake on return.
 *
 * NOTE: The Random command returns a fixed, predictable sequence when the
 * configuration zone is not locked.  Lock the config zone (see below) to
 * enable true hardware random number generation.
 */
bool atecc608c_random_bytes(atecc608c_t *dev, uint8_t *out, uint8_t len);

/* ==========================================================================
 * Configuration zone access
 *
 * The ATECC608C configuration zone is a 128-byte OTP-like region that
 * defines the chip's slot layout, key access policies, and I2C address.
 * It is written word-by-word before being permanently locked.
 *
 * Locking sequence:
 *   1. Call atecc608c_read_config_zone() to inspect the current contents.
 *   2. Check atecc608c_config_zone_is_locked() -- abort if already locked.
 *   3. Call atecc608c_write_config_word() for each word you want to change
 *      (only bytes 16..127 are writable; bytes 0..15 are factory-set).
 *   4. Call atecc608c_read_config_zone() again to get the final contents.
 *   5. Compute atecc608c_crc16() over all 128 bytes.
 *   6. Call atecc608c_lock_config_zone() with that CRC.
 *
 * All functions in this section require the chip to be awake.
 * ========================================================================== */

/*
 * Sentinel value for the summary_crc argument of atecc608c_lock_config_zone()
 * that requests locking WITHOUT the CRC integrity check.
 *
 * Using this in production is strongly discouraged: if the zone was
 * mis-programmed the chip will be permanently locked in a broken state.
 * Prefer always computing and passing the real CRC.
 */
#define ATECC608C_LOCK_NO_CRC  0xFFFFu

/*
 * Read the complete 128-byte configuration zone into out[128].
 *
 * Issues four 32-byte block reads (the maximum the Read command returns
 * in one call).  Validates the CRC on each response before copying.
 *
 * Returns true on success, false on I/O error or CRC mismatch.
 */
bool atecc608c_read_config_zone(atecc608c_t *dev, uint8_t out[128]);

/*
 * Write one 4-byte word to the configuration zone.
 *
 * byte_offset  Byte position within the config zone.  Must be a multiple
 *              of 4 and in the range [16, 128).  Bytes 0..15 are factory-
 *              programmed (serial number, revision) and cannot be written.
 *
 * data         Four bytes in the order they appear in the zone (i.e. the
 *              byte at byte_offset is data[0]).
 *
 * The chip must be awake.  Returns true on success.
 */
bool atecc608c_write_config_word(atecc608c_t *dev, uint8_t byte_offset,
                                  const uint8_t data[4]);

/*
 * Lock the configuration zone.
 *
 * summary_crc  CRC-16/IBM computed over all 128 bytes of the config zone
 *              exactly as they stand on the chip at the moment of locking
 *              (including the factory bytes 0..15 that you did not write).
 *              The chip re-computes the same CRC internally; if the values
 *              disagree the lock command is rejected, protecting against
 *              accidental locking of a corrupt or partially-written zone.
 *
 *              Pass ATECC608C_LOCK_NO_CRC to skip this check (not
 *              recommended for production use).
 *
 * *** WARNING: Locking the configuration zone is permanent and irreversible.
 *              After locking, the slot layout, key types, access policies,
 *              and I2C address cannot be changed under any circumstances.
 *              Always verify the zone contents before calling this function.
 *
 * The chip must be awake.  Returns true if the zone was successfully locked.
 */
bool atecc608c_lock_config_zone(atecc608c_t *dev, uint16_t summary_crc);

/*
 * Report whether the configuration zone is locked.
 *
 * Reads the LockConfig byte (byte 87 of the config zone) from the chip.
 * The value 0x55 means unlocked; any other value means locked.
 *
 * On success sets *out_locked and returns true.
 * Returns false on I/O error.
 * The chip must be awake.
 */
bool atecc608c_config_zone_is_locked(atecc608c_t *dev, bool *out_locked);

#ifdef __cplusplus
}
#endif

#endif