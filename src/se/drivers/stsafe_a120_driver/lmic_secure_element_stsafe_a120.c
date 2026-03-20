#include "lmic_secure_element_stsafe_a120.h"
#include "stsafe_a120_backend.h"

#include <string.h>

static stsafe_a120_backend_ctx_t g_stsafe_a120;

static LMIC_SecureElement_Error_t map_backend_status(stsafe_a120_backend_status_t st)
{
    switch (st) {
    case STSAFE_A120_BACKEND_STATUS_OK:
        return LMIC_SecureElement_Error_OK;
    case STSAFE_A120_BACKEND_STATUS_INVALID_PARAM:
        return LMIC_SecureElement_Error_InvalidParameter;
    case STSAFE_A120_BACKEND_STATUS_NOT_PROVISIONED:
        return LMIC_SecureElement_Error_NotProvisioned;
    case STSAFE_A120_BACKEND_STATUS_PERMISSION:
        return LMIC_SecureElement_Error_Permission;
    case STSAFE_A120_BACKEND_STATUS_UNSUPPORTED:
    case STSAFE_A120_BACKEND_STATUS_NOT_INITIALIZED:
    case STSAFE_A120_BACKEND_STATUS_IO_ERROR:
    case STSAFE_A120_BACKEND_STATUS_CRYPTO_ERROR:
    default:
        return LMIC_SecureElement_Error_Implementation;
    }
}

static int valid_key_selector(LMIC_SecureElement_KeySelector_t iKey)
{
    return iKey < LMIC_SecureElement_KeySelector_SIZE;
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_initialize(void)
{
    return map_backend_status(stsafe_a120_backend_init(&g_stsafe_a120));
}

uint8_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getRandomU1(void)
{
    uint8_t v = 0;
    (void)stsafe_a120_backend_random(&g_stsafe_a120, &v, 1);
    return v;
}

uint16_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getRandomU2(void)
{
    uint8_t b[2] = {0, 0};
    (void)stsafe_a120_backend_random(&g_stsafe_a120, b, 2);
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_fillRandomBuffer(uint8_t *buffer, uint8_t nBuffer)
{
    if (buffer == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_random(&g_stsafe_a120, buffer, nBuffer)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_setAppKey(const LMIC_SecureElement_Aes128Key_t *pAppKey)
{
    if (pAppKey == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_set_appkey(&g_stsafe_a120, pAppKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getAppKey(LMIC_SecureElement_Aes128Key_t *pAppKey)
{
    if (pAppKey == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_get_appkey(&g_stsafe_a120, pAppKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_setAppEUI(const LMIC_SecureElement_EUI_t *pAppEUI)
{
    if (pAppEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_set_appeui(&g_stsafe_a120, pAppEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getAppEUI(LMIC_SecureElement_EUI_t *pAppEUI)
{
    if (pAppEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_get_appeui(&g_stsafe_a120, pAppEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_setDevEUI(const LMIC_SecureElement_EUI_t *pDevEUI)
{
    if (pDevEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_set_deveui(&g_stsafe_a120, pDevEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getDevEUI(LMIC_SecureElement_EUI_t *pDevEUI)
{
    if (pDevEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_get_deveui(&g_stsafe_a120, pDevEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_setNwkSKey(
    const LMIC_SecureElement_Aes128Key_t *pNwkSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pNwkSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_set_nwkskey(&g_stsafe_a120, iKey, pNwkSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getNwkSKey(
    LMIC_SecureElement_Aes128Key_t *pNwkSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pNwkSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_get_nwkskey(&g_stsafe_a120, iKey, pNwkSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_setAppSKey(
    const LMIC_SecureElement_Aes128Key_t *pAppSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pAppSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_set_appskey(&g_stsafe_a120, iKey, pAppSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_getAppSKey(
    LMIC_SecureElement_Aes128Key_t *pAppSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pAppSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_get_appskey(&g_stsafe_a120, iKey, pAppSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_createJoinRequest(
    uint8_t *pJoinRequestBytes,
    LMIC_SecureElement_JoinFormat_t joinFormat)
{
    if (pJoinRequestBytes == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_create_join_request(&g_stsafe_a120, pJoinRequestBytes, joinFormat)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_decodeJoinAccept(
    const uint8_t *pJoinAcceptBytes,
    uint8_t nJoinAcceptBytes,
    uint8_t *pJoinAcceptClearText,
    LMIC_SecureElement_JoinFormat_t joinFormat)
{
    if (pJoinAcceptBytes == NULL || pJoinAcceptClearText == NULL || nJoinAcceptBytes == 0) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_decode_join_accept(
            &g_stsafe_a120,
            pJoinAcceptBytes,
            nJoinAcceptBytes,
            pJoinAcceptClearText,
            joinFormat)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_encodeMessage(
    const uint8_t *pMessage,
    uint8_t nMessage,
    uint8_t iPayload,
    uint8_t *pCipherTextBuffer,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pMessage == NULL || pCipherTextBuffer == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_encode_message(
            &g_stsafe_a120,
            pMessage,
            nMessage,
            iPayload,
            pCipherTextBuffer,
            iKey)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_verifyMIC(
    const uint8_t *pPhyPayload,
    uint8_t nPhyPayload,
    uint32_t devAddr,
    uint32_t FCntDown,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pPhyPayload == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_verify_mic(
            &g_stsafe_a120,
            pPhyPayload,
            nPhyPayload,
            devAddr,
            FCntDown,
            iKey)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_decodeMessage(
    const uint8_t *pPhyPayload,
    uint8_t nPhyPayload,
    uint32_t devAddr,
    uint32_t FCntDown,
    LMIC_SecureElement_KeySelector_t iKey,
    uint8_t *pClearTextBuffer)
{
    if (pPhyPayload == NULL || pClearTextBuffer == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_decode_message(
            &g_stsafe_a120,
            pPhyPayload,
            nPhyPayload,
            devAddr,
            FCntDown,
            iKey,
            pClearTextBuffer)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_StsafeA120_aes128Encrypt(
    const uint8_t *pKey,
    const uint8_t *pInput,
    uint8_t *pOutput)
{
    if (pKey == NULL || pInput == NULL || pOutput == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        stsafe_a120_backend_aes128_encrypt(&g_stsafe_a120, pKey, pInput, pOutput)
    );
}
