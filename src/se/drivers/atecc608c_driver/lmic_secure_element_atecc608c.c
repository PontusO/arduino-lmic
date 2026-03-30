#include "lmic_secure_element_atecc608c.h"
#include "atecc608c_backend.h"

#include <string.h>

static atecc608c_backend_ctx_t g_atecc608c;

static LMIC_SecureElement_Error_t map_backend_status(atecc608c_backend_status_t st)
{
    switch (st) {
    case ATECC608C_BACKEND_STATUS_OK:
        return LMIC_SecureElement_Error_OK;
    case ATECC608C_BACKEND_STATUS_INVALID_PARAM:
        return LMIC_SecureElement_Error_InvalidParameter;
    case ATECC608C_BACKEND_STATUS_NOT_PROVISIONED:
        return LMIC_SecureElement_Error_NotProvisioned;
    case ATECC608C_BACKEND_STATUS_PERMISSION:
        return LMIC_SecureElement_Error_Permission;
    case ATECC608C_BACKEND_STATUS_UNSUPPORTED:
    case ATECC608C_BACKEND_STATUS_NOT_INITIALIZED:
    case ATECC608C_BACKEND_STATUS_IO_ERROR:
    case ATECC608C_BACKEND_STATUS_CRYPTO_ERROR:
    default:
        return LMIC_SecureElement_Error_Implementation;
    }
}

static int valid_key_selector(LMIC_SecureElement_KeySelector_t iKey)
{
    return iKey < LMIC_SecureElement_KeySelector_SIZE;
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_initialize(void)
{
    return map_backend_status(atecc608c_backend_init(&g_atecc608c));
}

uint8_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getRandomU1(void)
{
    uint8_t v = 0;
    (void)atecc608c_backend_random(&g_atecc608c, &v, 1);
    return v;
}

uint16_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getRandomU2(void)
{
    uint8_t b[2] = {0, 0};
    (void)atecc608c_backend_random(&g_atecc608c, b, 2);
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_fillRandomBuffer(uint8_t *buffer, uint8_t nBuffer)
{
    if (buffer == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_random(&g_atecc608c, buffer, nBuffer)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_setAppKey(const LMIC_SecureElement_Aes128Key_t *pAppKey)
{
    if (pAppKey == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_set_appkey(&g_atecc608c, pAppKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getAppKey(LMIC_SecureElement_Aes128Key_t *pAppKey)
{
    if (pAppKey == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_get_appkey(&g_atecc608c, pAppKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_setAppEUI(const LMIC_SecureElement_EUI_t *pAppEUI)
{
    if (pAppEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_set_appeui(&g_atecc608c, pAppEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getAppEUI(LMIC_SecureElement_EUI_t *pAppEUI)
{
    if (pAppEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_get_appeui(&g_atecc608c, pAppEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_setDevEUI(const LMIC_SecureElement_EUI_t *pDevEUI)
{
    if (pDevEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_set_deveui(&g_atecc608c, pDevEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getDevEUI(LMIC_SecureElement_EUI_t *pDevEUI)
{
    if (pDevEUI == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_get_deveui(&g_atecc608c, pDevEUI->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_setNwkSKey(
    const LMIC_SecureElement_Aes128Key_t *pNwkSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pNwkSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_set_nwkskey(&g_atecc608c, iKey, pNwkSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getNwkSKey(
    LMIC_SecureElement_Aes128Key_t *pNwkSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pNwkSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_get_nwkskey(&g_atecc608c, iKey, pNwkSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_setAppSKey(
    const LMIC_SecureElement_Aes128Key_t *pAppSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pAppSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_set_appskey(&g_atecc608c, iKey, pAppSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_getAppSKey(
    LMIC_SecureElement_Aes128Key_t *pAppSKey,
    LMIC_SecureElement_KeySelector_t iKey)
{
    if (pAppSKey == NULL || !valid_key_selector(iKey)) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_get_appskey(&g_atecc608c, iKey, pAppSKey->bytes)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_createJoinRequest(
    uint8_t *pJoinRequestBytes,
    LMIC_SecureElement_JoinFormat_t joinFormat)
{
    if (pJoinRequestBytes == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_create_join_request(&g_atecc608c, pJoinRequestBytes, joinFormat)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_decodeJoinAccept(
    const uint8_t *pJoinAcceptBytes,
    uint8_t nJoinAcceptBytes,
    uint8_t *pJoinAcceptClearText,
    LMIC_SecureElement_JoinFormat_t joinFormat)
{
    if (pJoinAcceptBytes == NULL || pJoinAcceptClearText == NULL || nJoinAcceptBytes == 0) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_decode_join_accept(
            &g_atecc608c,
            pJoinAcceptBytes,
            nJoinAcceptBytes,
            pJoinAcceptClearText,
            joinFormat)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_encodeMessage(
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
        atecc608c_backend_encode_message(
            &g_atecc608c,
            pMessage,
            nMessage,
            iPayload,
            pCipherTextBuffer,
            iKey)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_verifyMIC(
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
        atecc608c_backend_verify_mic(
            &g_atecc608c,
            pPhyPayload,
            nPhyPayload,
            devAddr,
            FCntDown,
            iKey)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_decodeMessage(
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
        atecc608c_backend_decode_message(
            &g_atecc608c,
            pPhyPayload,
            nPhyPayload,
            devAddr,
            FCntDown,
            iKey,
            pClearTextBuffer)
    );
}

LMIC_SecureElement_Error_t LMIC_ABI_STD
LMIC_SecureElement_Atecc608c_aes128Encrypt(
    const uint8_t *pKey,
    const uint8_t *pInput,
    uint8_t *pOutput)
{
    if (pKey == NULL || pInput == NULL || pOutput == NULL) {
        return LMIC_SecureElement_Error_InvalidParameter;
    }

    return map_backend_status(
        atecc608c_backend_aes128_encrypt(&g_atecc608c, pKey, pInput, pOutput)
    );
}
