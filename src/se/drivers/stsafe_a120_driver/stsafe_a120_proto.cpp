#include "stsafe_a120_proto.h"

bool stsafe_a120_init(stsafe_a120_t *dev,
                      TwoWire *wire,
                      uint8_t i2c_addr_7bit,
                      int8_t reset_pin,
                      uint32_t i2c_clock_hz)
{
    if (!dev) {
        return false;
    }

    dev->initialized = false;

    if (!stsafe_a120_hal_init(&dev->hal, wire, i2c_addr_7bit, reset_pin, i2c_clock_hz)) {
        return false;
    }

    dev->initialized = stsafe_a120_hal_wait_ready(&dev->hal, 50);
    return dev->initialized;
}

bool stsafe_a120_reset_and_probe(stsafe_a120_t *dev)
{
    if (!dev) {
        return false;
    }

    if (dev->hal.reset_pin >= 0) {
        return stsafe_a120_hal_reset_pulse(&dev->hal);
    }

    return stsafe_a120_hal_wait_ready(&dev->hal, 50);
}

bool stsafe_a120_ping(stsafe_a120_t *dev)
{
    if (!dev || !dev->initialized) {
        return false;
    }

    return stsafe_a120_hal_probe(&dev->hal);
}

bool stsafe_a120_raw_exchange(stsafe_a120_t *dev,
                              const uint8_t *tx,
                              size_t tx_len,
                              uint8_t *rx,
                              size_t rx_len)
{
    if (!dev || !dev->initialized) {
        return false;
    }

    return stsafe_a120_hal_write_read(&dev->hal, tx, tx_len, rx, rx_len);
}

bool stsafe_a120_generate_random_stub(stsafe_a120_t *dev,
                                      uint8_t *out,
                                      size_t out_len)
{
    if (!dev || !out || out_len == 0) {
        return false;
    }

    /*
     * This is NOT the real Generate Random command yet.
     * It only proves that raw I2C transaction plumbing is callable.
     *
     * Replace this with the actual STSAFE command frame once you wire in
     * the official command encoding.
     */
    uint8_t dummy_tx[1] = { 0x00 };
    if (!stsafe_a120_raw_exchange(dev, dummy_tx, sizeof(dummy_tx), out, out_len)) {
        return false;
    }

    return true;
}