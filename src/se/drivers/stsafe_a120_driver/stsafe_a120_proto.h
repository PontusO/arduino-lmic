#ifndef STSAFE_A120_PROTO_H
#define STSAFE_A120_PROTO_H

#include "stsafe_a120_hal.h"

struct stsafe_a120_t {
    stsafe_a120_hal_t hal;
    bool initialized;
};

#ifdef __cplusplus
extern "C" {
#endif

bool stsafe_a120_init(stsafe_a120_t *dev,
                      TwoWire *wire,
                      uint8_t i2c_addr_7bit,
                      int8_t reset_pin,
                      uint32_t i2c_clock_hz);

bool stsafe_a120_reset_and_probe(stsafe_a120_t *dev);
bool stsafe_a120_ping(stsafe_a120_t *dev);

/*
 * Raw transaction placeholder.
 * You will replace this once you have the exact STSAFE command frame format
 * wired in from the command-set documentation / middleware.
 */
bool stsafe_a120_raw_exchange(stsafe_a120_t *dev,
                              const uint8_t *tx,
                              size_t tx_len,
                              uint8_t *rx,
                              size_t rx_len);

/*
 * Placeholder for first real command.
 * Currently just a transport stub, not a real STSAFE Generate Random command.
 */
bool stsafe_a120_generate_random_stub(stsafe_a120_t *dev,
                                      uint8_t *out,
                                      size_t out_len);

#ifdef __cplusplus
}
#endif

#endif