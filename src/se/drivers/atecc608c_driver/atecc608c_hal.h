#ifndef ATECC608C_HAL_H
#define ATECC608C_HAL_H

#include <Arduino.h>
#include <Wire.h>

struct atecc608c_hal_t {
    TwoWire *wire;
    uint8_t i2c_addr_7bit;
    int8_t reset_pin;
    uint32_t i2c_clock_hz;
};

#ifdef __cplusplus
extern "C" {
#endif

bool atecc608c_hal_init(atecc608c_hal_t *hal,
                          TwoWire *wire,
                          uint8_t i2c_addr_7bit,
                          int8_t reset_pin,
                          uint32_t i2c_clock_hz);

void atecc608c_hal_reset_assert(const atecc608c_hal_t *hal);
void atecc608c_hal_reset_release(const atecc608c_hal_t *hal);
bool atecc608c_hal_reset_pulse(const atecc608c_hal_t *hal);

bool atecc608c_hal_probe(const atecc608c_hal_t *hal);
bool atecc608c_hal_wait_ready(const atecc608c_hal_t *hal, uint32_t timeout_ms);

bool atecc608c_hal_write(const atecc608c_hal_t *hal,
                           const uint8_t *data,
                           size_t len);

bool atecc608c_hal_read(const atecc608c_hal_t *hal,
                          uint8_t *data,
                          size_t len);

bool atecc608c_hal_write_read(const atecc608c_hal_t *hal,
                                const uint8_t *tx,
                                size_t tx_len,
                                uint8_t *rx,
                                size_t rx_len);

void atecc608c_hal_scan(const atecc608c_hal_t *hal, Stream &out);


#ifdef __cplusplus
}
#endif

#endif