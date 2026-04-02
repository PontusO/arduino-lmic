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

/* ==========================================================================
 * Configuration zone: Read, Write, Lock
 * ========================================================================== */

/*
 * atecc608c_read_config_zone
 *
 * The 128-byte config zone is organised as 4 blocks of 32 bytes.  The Read
 * command (opcode 0x02) returns one block per call when param1 bit 7 is set.
 *
 * Command frame (8 bytes including the leading word-address byte 0x03):
 *
 *   [0x03, count=0x07, opcode=0x02, param1, addr_lo, addr_hi, crc_lo, crc_hi]
 *
 *   param1 = 0x80  -- bit 7 = 1 selects 32-byte read; bits [1:0] = 0 selects
 *                     the config zone (1 = OTP, 2 = data).
 *   addr_lo        -- block number shifted left by 3, giving the word offset
 *                     of the first word in that block.
 *   addr_hi = 0x00
 *
 * Response (35 bytes):
 *
 *   [count=0x23, data[32], crc_lo, crc_hi]
 *
 * The CRC covers all bytes from count through the last data byte (33 bytes).
 */
bool atecc608c_read_config_zone(atecc608c_t *dev, uint8_t out[128])
{
    if (!dev || !dev->initialized || !out) {
        return false;
    }

    for (uint8_t block = 0u; block < 4u; ++block) {

        /* Build the Read command frame for this 32-byte block. */
        uint8_t tx[8];
        tx[0] = 0x03u;                 /* word address: command */
        tx[1] = 0x07u;                 /* count (7 bytes: count+opcode+p1+p2[2]+crc[2]) */
        tx[2] = 0x02u;                 /* opcode: Read */
        tx[3] = 0x80u;                 /* param1: 32-byte read, config zone */
        tx[4] = (uint8_t)(block << 3); /* param2 lo: block << 3 = first word in block */
        tx[5] = 0x00u;                 /* param2 hi */
        uint16_t crc = atecc608c_crc16(&tx[1], 5u);
        tx[6] = (uint8_t)(crc & 0xFFu);
        tx[7] = (uint8_t)(crc >> 8);

        if (!atecc608c_hal_write(&dev->hal, tx, sizeof(tx))) {
            return false;
        }

        delay(2); /* tEXEC for Read: 2 ms max per datasheet */

        /*
         * Read the 35-byte response.
         * Byte 0 is the count (must be 35 = 0x23).
         * Bytes 1..32 are the 32 data bytes.
         * Bytes 33..34 are the CRC.
         */
        uint8_t rx[35];
        if (!atecc608c_hal_read(&dev->hal, rx, sizeof(rx))) {
            return false;
        }

        if (rx[0] != 35u) {
            return false; /* unexpected response length */
        }

        /* Validate CRC over count byte + 32 data bytes (33 bytes total). */
        uint16_t rx_crc_calc = atecc608c_crc16(rx, 33u);
        uint16_t rx_crc_recv = (uint16_t)rx[33] | ((uint16_t)rx[34] << 8);
        if (rx_crc_calc != rx_crc_recv) {
            return false;
        }

        /* Copy the 32 data bytes into the correct position in the output buffer. */
        memcpy(out + ((size_t)block * 32u), &rx[1], 32u);
    }

    return true;
}

/*
 * atecc608c_write_config_word
 *
 * Writes four bytes to one word in the configuration zone.
 *
 * The ATECC608C config zone address is encoded as:
 *   bits [2:0]: word index within the block (0..7)
 *   bits [5:3]: block number (0..3)
 *
 * So for byte_offset B:
 *   word_idx      = B / 4
 *   block         = word_idx / 8
 *   word_in_block = word_idx % 8
 *   param2_lo     = (block << 3) | word_in_block
 *
 * Command frame (12 bytes including word-address byte 0x03):
 *
 *   [0x03, count=0x0B, opcode=0x12, param1=0x00,
 *    addr_lo, addr_hi=0x00, d0, d1, d2, d3, crc_lo, crc_hi]
 *
 *   param1 = 0x00  -- bit 7 = 0 selects 4-byte write; bits [1:0] = 0 selects
 *                     the config zone.
 *   count  = 0x0B  -- 11 bytes: count + opcode + param1 + param2[2] +
 *                     data[4] + crc[2].
 *
 * CRC covers bytes 1..9 (9 bytes: count through the last data byte).
 *
 * Response (4 bytes): [count=0x04, status, crc_lo, crc_hi]
 * Status byte 0x00 = success; any other value is an error code.
 */
bool atecc608c_write_config_word(atecc608c_t *dev, uint8_t byte_offset,
                                  const uint8_t data[4])
{
    if (!dev || !dev->initialized || !data) {
        return false;
    }

    /*
     * Guard: bytes 0..15 are factory-programmed (serial number, revision)
     * and cannot be written.  byte_offset must also be word-aligned and
     * within the 128-byte zone.
     */
    if (byte_offset < 16u || byte_offset >= 128u || (byte_offset & 3u) != 0u) {
        return false;
    }

    /* Compute the word address for param2. */
    uint8_t word_idx      = byte_offset >> 2;          /* byte_offset / 4  */
    uint8_t block         = word_idx >> 3;             /* word_idx / 8     */
    uint8_t word_in_block = word_idx & 0x07u;          /* word_idx % 8     */
    uint8_t param2_lo     = (uint8_t)((block << 3) | word_in_block);

    uint8_t tx[12];
    tx[0]  = 0x03u;     /* word address: command */
    tx[1]  = 0x0Bu;     /* count = 11 */
    tx[2]  = 0x12u;     /* opcode: Write */
    tx[3]  = 0x00u;     /* param1: 4-byte write, config zone */
    tx[4]  = param2_lo;
    tx[5]  = 0x00u;     /* param2 hi (always 0 for config zone word writes) */
    tx[6]  = data[0];
    tx[7]  = data[1];
    tx[8]  = data[2];
    tx[9]  = data[3];
    uint16_t crc = atecc608c_crc16(&tx[1], 9u); /* CRC over count..data (9 bytes) */
    tx[10] = (uint8_t)(crc & 0xFFu);
    tx[11] = (uint8_t)(crc >> 8);

    if (!atecc608c_hal_write(&dev->hal, tx, sizeof(tx))) {
        return false;
    }

    /*
     * tEXEC for a config zone Write: 26 ms typical, 35 ms maximum.
     * We use the conservative maximum to guarantee correct operation
     * across temperature and supply voltage variation.
     */
    delay(35);

    /*
     * Read the 4-byte status response.
     * Byte 0: count (must be 4).
     * Byte 1: error code (0x00 = success).
     * Bytes 2..3: CRC over bytes 0..1.
     */
    uint8_t rx[4];
    if (!atecc608c_hal_read(&dev->hal, rx, sizeof(rx))) {
        return false;
    }

    if (rx[0] != 4u) {
        return false;
    }

    /* Validate response CRC over count byte + status byte (2 bytes). */
    uint16_t rx_crc_calc = atecc608c_crc16(rx, 2u);
    uint16_t rx_crc_recv = (uint16_t)rx[2] | ((uint16_t)rx[3] << 8);
    if (rx_crc_calc != rx_crc_recv) {
        return false;
    }

    return (rx[1] == 0x00u); /* status 0x00 = success */
}

/*
 * atecc608c_lock_config_zone
 *
 * Issues the Lock command (opcode 0x17) to permanently seal the config zone.
 *
 * Command frame (8 bytes including word-address byte 0x03):
 *
 *   [0x03, count=0x07, opcode=0x17, mode, param2_lo, param2_hi, crc_lo, crc_hi]
 *
 *   mode = 0x01  lock config zone, CRC check ENABLED  (recommended)
 *   mode = 0x81  lock config zone, CRC check DISABLED (ATECC608C_LOCK_NO_CRC)
 *
 * When CRC checking is enabled the chip re-computes a CRC-16/IBM over the
 * entire 128-byte config zone and compares it with param2 (little-endian).
 * If the values disagree the lock is rejected, preventing a mis-programmed
 * zone from being sealed permanently.
 *
 * Response (4 bytes): [count=0x04, status, crc_lo, crc_hi]
 */
bool atecc608c_lock_config_zone(atecc608c_t *dev, uint16_t summary_crc)
{
    if (!dev || !dev->initialized) {
        return false;
    }

    uint8_t mode;
    uint8_t param2_lo, param2_hi;

    if (summary_crc == ATECC608C_LOCK_NO_CRC) {
        /*
         * Bypass mode: the chip skips the CRC comparison.
         * Param2 must be 0x0000 when mode bit 7 is set.
         */
        mode      = 0x81u;
        param2_lo = 0x00u;
        param2_hi = 0x00u;
    } else {
        /*
         * Safe mode (recommended): the chip validates the CRC before locking.
         * The caller must compute the CRC over all 128 config zone bytes as
         * they exist on the chip -- including the factory bytes 0..15.
         */
        mode      = 0x01u;
        param2_lo = (uint8_t)(summary_crc & 0xFFu);
        param2_hi = (uint8_t)(summary_crc >> 8);
    }

    uint8_t tx[8];
    tx[0] = 0x03u;      /* word address: command */
    tx[1] = 0x07u;      /* count */
    tx[2] = 0x17u;      /* opcode: Lock */
    tx[3] = mode;
    tx[4] = param2_lo;
    tx[5] = param2_hi;
    uint16_t crc = atecc608c_crc16(&tx[1], 5u);
    tx[6] = (uint8_t)(crc & 0xFFu);
    tx[7] = (uint8_t)(crc >> 8);

    if (!atecc608c_hal_write(&dev->hal, tx, sizeof(tx))) {
        return false;
    }

    delay(35); /* tEXEC for Lock: 35 ms maximum per datasheet */

    uint8_t rx[4];
    if (!atecc608c_hal_read(&dev->hal, rx, sizeof(rx))) {
        return false;
    }

    if (rx[0] != 4u) {
        return false;
    }

    /* Validate response CRC. */
    uint16_t rx_crc_calc = atecc608c_crc16(rx, 2u);
    uint16_t rx_crc_recv = (uint16_t)rx[2] | ((uint16_t)rx[3] << 8);
    if (rx_crc_calc != rx_crc_recv) {
        return false;
    }

    return (rx[1] == 0x00u);
}

/*
 * atecc608c_config_zone_is_locked
 *
 * The LockConfig byte lives at offset 87 in the config zone, inside the
 * 4-byte word at byte offset 84 (word index 21 = block 2, word-in-block 5).
 *
 * A 4-byte Read command is used:
 *   param1 = 0x00  (4-byte read, config zone)
 *   param2 = (2 << 3) | 5 = 0x15  (word address for byte 84)
 *
 * Response (7 bytes): [count=0x07, byte84, byte85, byte86, byte87, crc_lo, crc_hi]
 *
 *   byte84 = UserExtra
 *   byte85 = UserExtraAdd
 *   byte86 = LockValue  (data+OTP zone lock status; 0x55 = unlocked)
 *   byte87 = LockConfig (config zone lock status;   0x55 = unlocked)
 */
bool atecc608c_config_zone_is_locked(atecc608c_t *dev, bool *out_locked)
{
    if (!dev || !dev->initialized || !out_locked) {
        return false;
    }

    uint8_t tx[8];
    tx[0] = 0x03u;  /* word address: command */
    tx[1] = 0x07u;  /* count */
    tx[2] = 0x02u;  /* opcode: Read */
    tx[3] = 0x00u;  /* param1: 4-byte read, config zone */
    tx[4] = 0x15u;  /* param2 lo: word address for byte 84 = (block 2 << 3) | word 5 */
    tx[5] = 0x00u;  /* param2 hi */
    uint16_t crc = atecc608c_crc16(&tx[1], 5u);
    tx[6] = (uint8_t)(crc & 0xFFu);
    tx[7] = (uint8_t)(crc >> 8);

    if (!atecc608c_hal_write(&dev->hal, tx, sizeof(tx))) {
        return false;
    }

    delay(2); /* tEXEC for Read: 2 ms max */

    /*
     * 4-byte read response: 7 bytes total.
     * rx[0] = count (must be 7)
     * rx[1] = byte 84 (UserExtra)
     * rx[2] = byte 85 (UserExtraAdd)
     * rx[3] = byte 86 (LockValue  -- data+OTP zone)
     * rx[4] = byte 87 (LockConfig -- config zone)
     * rx[5..6] = CRC over rx[0..4] (5 bytes)
     */
    uint8_t rx[7];
    if (!atecc608c_hal_read(&dev->hal, rx, sizeof(rx))) {
        return false;
    }

    if (rx[0] != 7u) {
        return false;
    }

    /* Validate CRC over count byte + 4 data bytes (5 bytes). */
    uint16_t rx_crc_calc = atecc608c_crc16(rx, 5u);
    uint16_t rx_crc_recv = (uint16_t)rx[5] | ((uint16_t)rx[6] << 8);
    if (rx_crc_calc != rx_crc_recv) {
        return false;
    }

    /*
     * rx[4] = LockConfig.  0x55 is the factory-default "unlocked" value.
     * Any other value (in practice 0x00) means the zone is locked.
     */
    *out_locked = (rx[4] != 0x55u);
    return true;
}

/* ==========================================================================
 * Legacy stubs (kept for backward compatibility)
 * ========================================================================== */

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