/*

Module:  arduino_lmic.h

Function:
        Arduino-LMIC C++ top-level include file

Copyright & License:
        See accompanying LICENSE file.

Author:
        Matthijs Kooijman       2015
        Terry Moore, MCCI       November 2018

*/

#pragma once

#ifndef _ARDUINO_LMIC_H_
# define _ARDUINO_LMIC_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "lmic/lmic.h"
#include "lmic/lmic_bandplan.h"
#include "lmic/lmic_util.h"

#ifdef __cplusplus
}
#endif

/*
 * ATECC608C secure element driver.
 *
 * These headers include C++ dependencies (Wire.h, Arduino.h) and must be
 * outside the extern "C" block.  They carry their own LMIC_BEGIN_DECLS /
 * LMIC_END_DECLS guards so that the C-linkage declarations inside them are
 * correct regardless of whether the translation unit is C or C++.
 */
#include "se/drivers/atecc608c_driver/atecc608c_proto.h"
#include "se/drivers/atecc608c_driver/atecc608c_backend.h"
#include "se/drivers/atecc608c_driver/lmic_secure_element_atecc608c.h"

#endif /* _ARDUINO_LMIC_H_ */
