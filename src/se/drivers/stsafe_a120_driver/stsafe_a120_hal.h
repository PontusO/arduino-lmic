#ifndef STSAFE_A120_HAL_H
#define STSAFE_A120_HAL_H

#include <Arduino.h>
#include <Wire.h>

struct stsafe_a120_hal_t {
    TwoWire *wire;
    uint8_t i2c_addr_7bit;
    int8_t reset_pin;
    uint32_t i2c_clock_hz;
};

#ifdef __cplusplus
extern "C" {
#endif

bool stsafe_a120_hal_init(stsafe_a120_hal_t *hal,
                          TwoWire *wire,
                          uint8_t i2c_addr_7bit,
                          int8_t reset_pin,
                          uint32_t i2c_clock_hz);

void stsafe_a120_hal_reset_assert(const stsafe_a120_hal_t *hal);
void stsafe_a120_hal_reset_release(const stsafe_a120_hal_t *hal);
bool stsafe_a120_hal_reset_pulse(const stsafe_a120_hal_t *hal);

bool stsafe_a120_hal_probe(const stsafe_a120_hal_t *hal);
bool stsafe_a120_hal_wait_ready(const stsafe_a120_hal_t *hal, uint32_t timeout_ms);

bool stsafe_a120_hal_write(const stsafe_a120_hal_t *hal,
                           const uint8_t *data,
                           size_t len);

bool stsafe_a120_hal_read(const stsafe_a120_hal_t *hal,
                          uint8_t *data,
                          size_t len);

bool stsafe_a120_hal_write_read(const stsafe_a120_hal_t *hal,
                                const uint8_t *tx,
                                size_t tx_len,
                                uint8_t *rx,
                                size_t rx_len);

void stsafe_a120_hal_scan(const stsafe_a120_hal_t *hal, Stream &out);


#ifdef __cplusplus
}
#endif

#endif