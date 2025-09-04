/*

Module:  getpinmap_heltec_lora32_v3.cpp

Function:
        Arduino-LMIC C++ HAL pinmap for Heltec Wireless Stick Lite V3 and Wifi Lora32 V3

Copyright & License:
        See accompanying LICENSE file.

Author:
        Tristan Webber, Shrunk Innovation Labs  July 2023

*/

#if defined(ARDUINO_heltec_wifi_lora_32_V3)

#include <arduino_lmic_hal_boards.h>
#include <Arduino.h>

#include "../lmic/oslmic.h"

namespace Arduino_LMIC
{

class HalConfiguration_heltec_lora32_v3 : public HalConfiguration_t
{
public:
    enum DIGITAL_PINS : uint8_t
    {
        PIN_SX1262_NSS = SS,
        PIN_SX1262_NRESET = RST_LoRa,
        PIN_SX1262_BUSY = BUSY_LoRa,
        PIN_SX1262_DIO1 = DIO0,
        PIN_SX1262_DIO2 = HalPinmap_t::UNUSED_PIN,
        PIN_SX1262_DIO3 = HalPinmap_t::UNUSED_PIN,
        PIN_SX1262_ANT_SWITCH_RX = HalPinmap_t::UNUSED_PIN,
        PIN_SX1262_ANT_SWITCH_TX_BOOST = HalPinmap_t::UNUSED_PIN,
        PIN_SX1262_ANT_SWITCH_TX_RFO = HalPinmap_t::UNUSED_PIN,
        PIN_VDD_BOOST_ENABLE = HalPinmap_t::UNUSED_PIN,
    };

    virtual u1_t queryBusyPin(void) override { return HalConfiguration_heltec_lora32_v3::PIN_SX1262_BUSY; };
    
    virtual bool queryUsingDcdc(void) override { return true; };

    virtual bool queryUsingDIO2AsRfSwitch(void) override { return true; };

    virtual bool queryUsingDIO3AsTCXOSwitch(void) override { return true; };
};

static HalConfiguration_heltec_lora32_v3 myConfig;

static const HalPinmap_t myPinmap =
    {
        .nss = HalConfiguration_heltec_lora32_v3::PIN_SX1262_NSS,
        .rxtx = HalConfiguration_heltec_lora32_v3::PIN_SX1262_ANT_SWITCH_RX,
        .rst = HalConfiguration_heltec_lora32_v3::PIN_SX1262_NRESET,
        .dio = {
            HalConfiguration_heltec_lora32_v3::PIN_SX1262_DIO1,
            HalConfiguration_heltec_lora32_v3::PIN_SX1262_DIO2,
            HalConfiguration_heltec_lora32_v3::PIN_SX1262_DIO3,
        },
        .rxtx_rx_active = 0,
        .rssi_cal = 10,
        .spi = &SPI,
        .spi_freq = 8000000, /* 8MHz */
        .pConfig = &myConfig};

const HalPinmap_t *GetPinmap_heltec_lora32_v3(void)
{
    return &myPinmap;
}

}; // namespace Arduino_LMIC

#endif // defined(ARDUINO_heltec_wifi_lora_32_V3)