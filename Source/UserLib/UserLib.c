/*
 * @file
 *
 * @brief Microservice API static library source file. This source file/library
 *        runs in the caller execution.
 *
 ******************************************************************************/

/********************************* INCLUDES ***********************************/

#include "us-tinyAES.h"

#include "us_Internal.h"

#include "uService.h"

/***************************** MACRO DEFINITIONS ******************************/

/***************************** TYPE DEFINITIONS *******************************/
typedef struct
{
    struct
    {
        uint32_t initialised        : 1;
    } flags;

    /*
     * The "Execution Index" is a system wide enumaration by the Microservice Runtime
     * to interact with the Microservice.
     */
    uint32_t execIndex;
} uS_UserLibSettings;

/**************************** FUNCTION PROTOTYPES *****************************/

/******************************** VARIABLES ***********************************/
PRIVATE uS_UserLibSettings userLibSettings;

PRIVATE const char usName[SYS_EXEC_NAME_MAX_LENGTH] = USERVICE_NAME;

/***************************** PRIVATE FUNCTIONS *******************************/

/***************************** PUBLIC FUNCTIONS *******************************/
#define INITIALISE_FUNCTIONEXPAND(a, b, c) a##b##c
#define INITIALISE_FUNCTION(name) INITIALISE_FUNCTIONEXPAND(us_, name, _Initialise)
SysStatus INITIALISE_FUNCTION(USERVICE_NAME_NONSTR)(void)
{
    /* Get the Microservice Index to interact with the Microservice */
    return uService_Initialise(usName, &userLibSettings.execIndex);
}

void us_tinyAES_init_ctx_iv(struct us_tinyAES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
    const uint32_t timeoutInMs = 2000;
    SysStatus retVal;

    usResponsePackage response;
    usRequestPackage request;

    {
        request.header.operation = usOp_init_ctx_iv;
        request.header.length = sizeof(request);
        memcpy(request.payload.init_ctx_iv.key, key, sizeof request.payload.init_ctx_iv.key);
        memcpy(request.payload.init_ctx_iv.iv, iv, sizeof request.payload.init_ctx_iv.iv);
    };

    retVal = uService_RequestBlocker(userLibSettings.execIndex, (uServicePackage*)&request, (uServicePackage*)&response, timeoutInMs);

    // TODO We need to return the error, maybe a new API like Last Error
    (void)response.header.status;

    if (retVal == SysStatus_Success && response.header.status == usStatus_Success)
    {
        ctx->ctx = response.payload.init_ctx_iv.ctx;
    }
}

void us_tinyAES_deinit_ctx(struct us_tinyAES_ctx* ctx)
{
    const uint32_t timeoutInMs = 2000;
    SysStatus retVal;

    usResponsePackage response;
    usRequestPackage request;

    {
        request.header.operation = usOp_deinit_ctx_iv;
        request.header.length = sizeof(request);
        request.payload.deinit_ctx.ctx = ctx->ctx;
    };

    retVal = uService_RequestBlocker(userLibSettings.execIndex, (uServicePackage*)&request, (uServicePackage*)&response, timeoutInMs);

    // TODO We need to return the error, maybe a new API like Last Error
    (void)response.header.status;
}



void us_tinyAES_CBC_encrypt_buffer(struct us_tinyAES_ctx* ctx, uint8_t* buf, size_t length)
{
    const uint32_t timeoutInMs = 2000;
    SysStatus retVal;

    usResponsePackage response;
    usRequestPackage request;

    {
        request.header.operation = usOp_cbc_enc;
        request.header.length = sizeof(request);
        request.payload.cbc_enc_dec.ctx = ctx->ctx;
        memcpy(request.payload.cbc_enc_dec.buf, buf, AES_BLOCKLEN);
    };

    retVal = uService_RequestBlocker(userLibSettings.execIndex, (uServicePackage*)&request, (uServicePackage*)&response, timeoutInMs);

    // TODO We need to return the error, maybe a new API like Last Error
    (void)response.header.status;

    if (retVal == SysStatus_Success && response.header.status == usStatus_Success)
    {
        memcpy(buf, response.payload.cbc_enc_dec.buf, AES_BLOCKLEN);
    }
}

void us_tinyAES_CBC_decrypt_buffer(struct us_tinyAES_ctx* ctx, uint8_t* buf, size_t length)
{
    const uint32_t timeoutInMs = 2000;
    SysStatus retVal;

    usResponsePackage response;
    usRequestPackage request;

    {
        request.header.operation = usOp_cbc_dec;
        request.header.length = sizeof(request);
        request.payload.cbc_enc_dec.ctx = ctx->ctx;
        memcpy(request.payload.cbc_enc_dec.buf, buf, AES_BLOCKLEN);
    };

    retVal = uService_RequestBlocker(userLibSettings.execIndex, (uServicePackage*)&request, (uServicePackage*)&response, timeoutInMs);

    // TODO We need to return the error, maybe a new API like Last Error
    (void)response.header.status;

    if (retVal == SysStatus_Success && response.header.status == usStatus_Success)
    {
        memcpy(buf, response.payload.cbc_enc_dec.buf, AES_BLOCKLEN);
    }
}
