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

#ifdef __cplusplus
}
#endif

#endif