// project-specific definitions
#define CFG_eu868 1
//#define CFG_us915 1
//#define CFG_au915 1
//#define CFG_as923 1
// #define LMIC_COUNTRY_CODE LMIC_COUNTRY_CODE_JP      /* for as923-JP; also define CFG_as923 */
//#define CFG_kr920 1
//#define CFG_in866 1
#define CFG_sx1276_radio 1
#define LMIC_ENABLE_class_c 1
//#define CFG_sx1261_radio 1
//#define CFG_sx1262_radio 1
//#define ARDUINO_heltec_wifi_lora_32_V3
//#define LMIC_USE_INTERRUPTS
//#define LMIC_CFG_SecureElement_DRIVER Atecc608c

//#define LMIC_DEBUG_LEVEL 2
// NOTE: do NOT use LMIC_PRINTF_TO on the Adafruit nRF52 core -- it pulls in
// fopencookie/cookie_io_functions_t (a GNU libc extension the newlib-nano
// here doesn't expose) and fails to compile. Route stack debug through a
// C-linkage function instead; defined in the sketch's lmic_debug.cpp.
//#define LMIC_DEBUG_PRINTF_FN lmic_debug_printf
