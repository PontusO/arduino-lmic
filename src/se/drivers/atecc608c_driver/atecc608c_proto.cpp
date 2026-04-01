/*******************************************************************************
 * Copyright (c) 2026 Ilabs AB
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * ATECC608C protocol layer (implementation).
 *
 *******************************************************************************/

#include "atecc608c_proto.h"

static bool atecc608c_expect_wake_response(const uint8_t *buf, size_t len)
{
    if (!buf || len < 4) {
        return false;
    }

    /* Observed wake/status response on your hardware */
    return (buf[0] == 0x04 &&
            buf[1] == 0x11 &&
            buf[2] == 0x33 &&
            buf[3] == 0x43);
}

bool atecc608c_init(atecc608c_t *dev,
                    TwoWire *wire,
                    uint8_t i2c_addr_7bit,
                    int8_t reset_pin,
                    uint32_t i2c_clock_hz)
{
    if (!dev) {
        return false;
    }

    dev->initialized = false;

    if (!atecc608c_hal_init(&dev->hal, wire, i2c_addr_7bit, reset_pin, i2c_clock_hz)) {
        return false;
    }

    /*
     * The ATECC608C is in sleep mode at power-on and will NOT ACK a plain
     * I2C address probe.  Instead we send the wake token and verify the
     * 4-byte wake response -- that proves the chip is present and responsive.
     * We then immediately put it back to sleep so it is in a defined state
     * after init returns.
     */
    dev->initialized = true;   /* needed so wake/sleep helpers will run */

    uint8_t wake_resp[4];
    atecc608c_hal_send_wake_token(&dev->hal);
    if (!atecc608c_hal_read(&dev->hal, wake_resp, 4) ||
        !atecc608c_expect_wake_response(wake_resp, 4)) {
        dev->initialized = false;
        return false;
    }

    /* Put chip back to sleep; leave it in a known state for the caller. */
    uint8_t sleep_wa = 0x01u;
    atecc608c_hal_write(&dev->hal, &sleep_wa, 1);

    return true;
}

bool atecc608c_reset_and_probe(atecc608c_t *dev)
{
    if (!dev || !dev->initialized) {
        return false;
    }

    if (dev->hal.reset_pin >= 0) {
        return atecc608c_hal_reset_pulse(&dev->hal);
    }

    return atecc608c_hal_probe(&dev->hal);
}

bool atecc608c_wake(atecc608c_t *dev, uint8_t wake_resp[4])
{
    if (!dev || !dev->initialized || !wake_resp) {
        return false;
    }

    /*
     * Wake sequence per ATECC608C datasheet:
     * 1. Send the wake token to I2C address 0x00 (not the device address).
     *    A sleeping chip ignores its own address; the 0x00 token is what
     *    pulls SDA low for tWLO and triggers wake-up.
     * 2. Read the 4-byte wake response from the device's real address.
     */
    atecc608c_hal_send_wake_token(&dev->hal);

    if (!atecc608c_hal_read(&dev->hal, wake_resp, 4)) {
        return false;
    }

    return atecc608c_expect_wake_response(wake_resp, 4);
}

bool atecc608c_ping(atecc608c_t *dev)
{
    uint8_t wake_resp[4];
    return atecc608c_wake(dev, wake_resp);
}

bool atecc608c_raw_exchange(atecc608c_t *dev,
                            const uint8_t *tx,
                            size_t tx_len,
                            uint8_t *rx,
                            size_t rx_len)
{
    if (!dev || !dev->initialized) {
        return false;
    }

    /*
     * For now, this is still just a transport helper.
     * We can refine timing/polling later once real commands are added.
     */
    return atecc608c_hal_write_read(&dev->hal, tx, tx_len, rx, rx_len);
}

uint16_t atecc608c_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        for (uint8_t bit = 0x01u; bit != 0u; bit <<= 1) {
            uint8_t data_bit = (data[i] & bit) ? 1u : 0u;
            uint8_t crc_bit  = (uint8_t)((crc >> 15) & 1u);
            crc = (uint16_t)(crc << 1);
            if (data_bit != crc_bit)
                crc ^= 0x8005u;
        }
    }
    return crc;
}

bool atecc608c_sleep(atecc608c_t *dev)
{
    if (!dev || !dev->initialized) {
        return false;
    }
    uint8_t wa = 0x01u; /* Sleep word address */
    return atecc608c_hal_write(&dev->hal, &wa, 1);
}

bool atecc608c_idle(atecc608c_t *dev)
{
    if (!dev || !dev->initialized) {
        return false;
    }
    uint8_t wa = 0x02u; /* Idle word address */
    return atecc608c_hal_write(&dev->hal, &wa, 1);
}

bool atecc608c_random_bytes(atecc608c_t *dev, uint8_t *out, uint8_t len)
{
    if (!dev || !dev->initialized || !out || len == 0u || len > 32u) {
        return false;
    }

    /*
     * Random command packet layout (8 bytes total):
     *   [0] 0x03  word address: command
     *   [1] 0x07  count (7 = count + opcode + param1 + param2[2] + crc[2])
     *   [2] 0x1B  opcode: Random
     *   [3] 0x00  param1: mode (0 = generate and update seed)
     *   [4] 0x00  param2 low
     *   [5] 0x00  param2 high
     *   [6..7]    CRC-16 over bytes [1..5]
     */
    uint8_t tx[8];
    tx[0] = 0x03u;
    tx[1] = 0x07u;
    tx[2] = 0x1Bu;
    tx[3] = 0x00u;
    tx[4] = 0x00u;
    tx[5] = 0x00u;
    uint16_t crc = atecc608c_crc16(&tx[1], 5);
    tx[6] = (uint8_t)(crc & 0xFFu);
    tx[7] = (uint8_t)(crc >> 8);

    if (!atecc608c_hal_write(&dev->hal, tx, sizeof(tx))) {
        return false;
    }

    delay(25); /* tEXEC for Random: 23 ms max per datasheet */

    /*
     * Response layout (35 bytes):
     *   [0]     0x23  count (35)
     *   [1..32] random data (32 bytes)
     *   [33..34] CRC-16 over bytes [0..32]
     */
    uint8_t rx[35];
    if (!atecc608c_hal_read(&dev->hal, rx, sizeof(rx))) {
        return false;
    }

    if (rx[0] != 35u) {
        return false;
    }

    uint16_t rx_crc_calc = atecc608c_crc16(rx, 33);
    uint16_t rx_crc_recv = (uint16_t)rx[33] | ((uint16_t)rx[34] << 8);
    if (rx_crc_calc != rx_crc_recv) {
        return false;
    }

    memcpy(out, &rx[1], len);
    return true;
}

bool atecc608c_generate_random_stub(atecc608c_t *dev,
                                    uint8_t *out,
                                    size_t out_len)
{
    uint8_t wake_resp[4];

    if (!dev || !out || out_len < 4) {
        return false;
    }

    if (!atecc608c_wake(dev, wake_resp)) {
        return false;
    }

    /*
     * For now, return the wake response so the caller can verify protocol behavior.
     * This is intentionally not random data yet.
     */
    out[0] = wake_resp[0];
    out[1] = wake_resp[1];
    out[2] = wake_resp[2];
    out[3] = wake_resp[3];

    for (size_t i = 4; i < out_len; ++i) {
        out[i] = 0xFF;
    }

    return true;
}