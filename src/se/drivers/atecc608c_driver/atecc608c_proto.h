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
 */
bool atecc608c_random_bytes(atecc608c_t *dev, uint8_t *out, uint8_t len);

#ifdef __cplusplus
}
#endif

#endif