/*

Module:  getpinmap_ttgo_tbeam_s3.cpp.cpp

Function:
        Arduino-LMIC C++ HAL pinmap for T-Beam S3 Core and T-Beam Supreme

Copyright & License:
        See accompanying LICENSE file.

*/

#if defined(ARDUINO_TTGO_T_BEAM_S3)

#include <arduino_lmic_hal_boards.h>
#include <Arduino.h>

#include "../lmic/oslmic.h"

namespace Arduino_LMIC {

    class HalConfiguration_ttgo_tbeam_s3 : public HalConfiguration_t {
    public:
        enum DIGITAL_PINS : uint8_t {
            PIN_SX1262_NSS = 10,
            PIN_SX1262_NRESET = 5,
            PIN_SX1262_BUSY = 4,
            PIN_SX1262_DIO1 = 1,
            PIN_SX1262_DIO2 = HalPinmap_t::UNUSED_PIN,
            PIN_SX1262_DIO3 = HalPinmap_t::UNUSED_PIN,
            PIN_SX1262_ANT_SWITCH_RX = HalPinmap_t::UNUSED_PIN,
            PIN_SX1262_ANT_SWITCH_TX_BOOST = HalPinmap_t::UNUSED_PIN,
            PIN_SX1262_ANT_SWITCH_TX_RFO = HalPinmap_t::UNUSED_PIN,
            PIN_VDD_BOOST_ENABLE = HalPinmap_t::UNUSED_PIN,
        };

        virtual u1_t queryBusyPin(void) override { return HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_BUSY; };

        virtual bool queryUsingDcdc(void) override { return true; };

        virtual bool queryUsingDIO2AsRfSwitch(void) override { return true; };

        virtual bool queryUsingDIO3AsTCXOSwitch(void) override { return true; };
    };

    static HalConfiguration_ttgo_tbeam_s3 myConfig;

    static const HalPinmap_t myPinmap =
    {
        .nss = HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_NSS,
        .rxtx = HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_ANT_SWITCH_RX,
        .rst = HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_NRESET,
        .dio = {
            HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_DIO1,
            HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_DIO2,
            HalConfiguration_ttgo_tbeam_s3::PIN_SX1262_DIO3,
        },
        .rxtx_rx_active = 0,
        .rssi_cal = 8,
        .spi = &SPI,
        .spi_freq = 8000000, /* 8MHz */
        .pConfig = &myConfig
    };

    const HalPinmap_t* GetPinmap_ttgo_tbeam_s3(void) {
        return &myPinmap;
    }

}; // namespace Arduino_LMIC

#endif // defined(ARDUINO_TTGO_T_BEAM_S3)