#include "atecc608c_hal.h"

static constexpr uint32_t ATECC608C_RESET_READY_DELAY_MS = 20;   // datasheet max tI2C_READY
static constexpr uint32_t ATECC608C_STANDBY_WAKE_US      = 100;  // >60 us, rounded safely

bool atecc608c_hal_init(atecc608c_hal_t *hal,
                          TwoWire *wire,
                          uint8_t i2c_addr_7bit,
                          int8_t reset_pin,
                          uint32_t i2c_clock_hz)
{
    if (!hal || !wire) {
        return false;
    }

    hal->wire = wire;
    hal->i2c_addr_7bit = i2c_addr_7bit;
    hal->reset_pin = reset_pin;
    hal->i2c_clock_hz = i2c_clock_hz;

    hal->wire->begin();
    hal->wire->setClock(i2c_clock_hz);

    if (reset_pin >= 0) {
        pinMode(reset_pin, OUTPUT);
        digitalWrite(reset_pin, LOW);
        delay(1);
        digitalWrite(reset_pin, HIGH);
        delay(ATECC608C_RESET_READY_DELAY_MS);
    }

    return true;
}

void atecc608c_hal_reset_assert(const atecc608c_hal_t *hal)
{
    if (!hal || hal->reset_pin < 0) {
        return;
    }
    digitalWrite(hal->reset_pin, LOW);
}

void atecc608c_hal_reset_release(const atecc608c_hal_t *hal)
{
    if (!hal || hal->reset_pin < 0) {
        return;
    }
    digitalWrite(hal->reset_pin, HIGH);
}

bool atecc608c_hal_reset_pulse(const atecc608c_hal_t *hal)
{
    if (!hal || hal->reset_pin < 0) {
        return false;
    }

    atecc608c_hal_reset_assert(hal);
    delay(1);  // comfortably above 5 us minimum pulse width
    atecc608c_hal_reset_release(hal);
    delay(ATECC608C_RESET_READY_DELAY_MS);

    return atecc608c_hal_wait_ready(hal, 50);
}

bool atecc608c_hal_probe(const atecc608c_hal_t *hal)
{
    if (!hal || !hal->wire) {
        return false;
    }

    hal->wire->beginTransmission(hal->i2c_addr_7bit);
    uint8_t err = hal->wire->endTransmission(true);
    return (err == 0);
}

bool atecc608c_hal_wait_ready(const atecc608c_hal_t *hal, uint32_t timeout_ms)
{
    if (!hal) {
        return false;
    }

    const uint32_t t0 = millis();

    while ((millis() - t0) < timeout_ms) {
        if (atecc608c_hal_probe(hal)) {
            return true;
        }
        delayMicroseconds(ATECC608C_STANDBY_WAKE_US);
        delay(1);
    }

    return false;
}

bool atecc608c_hal_write(const atecc608c_hal_t *hal,
                           const uint8_t *data,
                           size_t len)
{
    if (!hal || !hal->wire || (!data && len != 0)) {
        return false;
    }

    hal->wire->beginTransmission(hal->i2c_addr_7bit);
    size_t written = hal->wire->write(data, len);
    uint8_t err = hal->wire->endTransmission(true);

    return (written == len) && (err == 0);
}

bool atecc608c_hal_read(const atecc608c_hal_t *hal,
                          uint8_t *data,
                          size_t len)
{
    if (!hal || !hal->wire || (!data && len != 0)) {
        return false;
    }

    size_t got = hal->wire->requestFrom((int)hal->i2c_addr_7bit, (int)len, (int)true);
    if (got != len) {
        while (hal->wire->available()) {
            (void)hal->wire->read();
        }
        return false;
    }

    for (size_t i = 0; i < len; ++i) {
        if (!hal->wire->available()) {
            return false;
        }
        data[i] = (uint8_t)hal->wire->read();
    }

    return true;
}

bool atecc608c_hal_write_read(const atecc608c_hal_t *hal,
                                const uint8_t *tx,
                                size_t tx_len,
                                uint8_t *rx,
                                size_t rx_len)
{
    if (!atecc608c_hal_write(hal, tx, tx_len)) {
        return false;
    }

    delayMicroseconds(ATECC608C_STANDBY_WAKE_US);

    if (rx_len == 0) {
        return true;
    }

    return atecc608c_hal_read(hal, rx, rx_len);
}

void atecc608c_hal_scan(const atecc608c_hal_t *hal, Stream &out)
{
    if (!hal || !hal->wire) {
        out.println("HAL not initialized");
        return;
    }

    out.println("I2C scan:");
    for (uint8_t addr = 0x08; addr <= 0x77; ++addr) {
        hal->wire->beginTransmission(addr);
        uint8_t err = hal->wire->endTransmission(true);
        if (err == 0) {
            out.print("  ACK at 0x");
            if (addr < 16) out.print('0');
            out.println(addr, HEX);
        }
    }
}