#define LOG_ERROR_ENABLED   1
#define LOG_WARNING_ENABLED 1
#define LOG_INFO_ENABLED    1
#include "uService.h"

#include "us-tinyAES.h"
#include "tiny-AES-c/aes.h"

#include "us_Internal.h"

#ifndef AES256
/* There is no compile switch to enable/disable in the library. It must be done explicityly :(
 *  So, let us not miss in case updates on the commits
 */
#error "AES -256 not defined in aes.h"
#endif

#ifndef CFG_US_MAX_NUM_OF_SESSION
#define CFG_US_MAX_NUM_OF_SESSION   1       /* Let us allow one session at a time */
#endif

typedef struct
{
    struct
    {
        uint32_t inUse      : 1;
        uint32_t sessionID  : 16;
    } flags;
    struct AES_ctx ctx;
} UserSession;

typedef struct
{
    UserSession userSessions[CFG_US_MAX_NUM_OF_SESSION];
    uint32_t numOfSessions;
} usSettings;

PRIVATE void startService(void);
PRIVATE void processRequest(uint8_t senderID, usRequestPackage* request);
PRIVATE void sendError(uint8_t receiverID, uint16_t operation, uint8_t status);

PRIVATE usSettings settings;

int main()
{
    SysStatus retVal;

    uService_PrintIntro();

    SYS_INITIALISE_IPC_MESSAGEBOX(retVal, CFG_US_MAX_NUM_OF_SESSION);
    if (retVal != SysStatus_Success)
    {
        LOG_ERROR("Failed to initialise MessageBox. Error : %d", retVal);
    }
    else
    {
        startService();
    }

    LOG_ERROR("Exiting the Microservice...");
    Sys_Exit();
}

PRIVATE void startService(void)
{
    usRequestPackage request;

    uint32_t sequenceNo;
    (void)sequenceNo;
    usStatus responseStatus;
    uint8_t senderID = 0xFF;

    while (true)
    {
        bool dataReceived = false;
        uint32_t receivedLen = 0;
        responseStatus = usStatus_Success;

        (void)Sys_IsMessageReceived(&dataReceived, &receivedLen, &sequenceNo);
        if (!dataReceived || receivedLen == 0)
        {
            /* Sleep until receive an IPC message */
            Sys_WaitForEvent(SysEvent_IPCMessage);

            continue;
        }

        if (receivedLen <= USERVICE_PACKAGE_HEADER_SIZE)
        {
            responseStatus = usStatus_InvalidParam_UnsufficientSize;
            LOG_PRINTF(" > Unsufficint Mandatory Received Length (%d)/(%d)",
                receivedLen, USERVICE_PACKAGE_HEADER_SIZE);
        }

#if 0
        if (responseStatus == usStatus_Success && 
            receivedLen > <PACKAGE_MAX_SIZE>)
        {
            responseStatus = usStatus_InvalidParam_SizeExceedAllowed;

            LOG_PRINTF(" > Received Length (%d) exceed than allowed length(%d)",
                receivedLen, <PACKAGE_MAX_SIZE>);

            /* Let us just get the header, as not need for the payload */
            receivedLen = USERVICE_PACKAGE_HEADER_SIZE;
        }
#endif

        /* Get the message */
        (void)Sys_ReceiveMessage(&senderID, (uint8_t*)&request, receivedLen, &sequenceNo);

        /* Do not process the message if there was an error */
        if (responseStatus != usStatus_Success)
        {
            sendError(senderID, request.header.operation, responseStatus);
            continue;
        }

        /* Process the request */
        processRequest(senderID, &request);
    }
}

#define SESSION_ID(_execId, _index)       ((_execId)<<8 | (_index))
PRIVATE ALWAYS_INLINE uint32_t getSessionID(uint8_t senderID, struct AES_ctx** ctx)
{
    for (int i = 0; i < CFG_US_MAX_NUM_OF_SESSION; i++)
    {
        UserSession* session = &settings.userSessions[i];
        if (!session->flags.inUse)
        {
            session->flags.inUse = true;
            session->flags.sessionID = SESSION_ID(senderID, i);
            settings.numOfSessions++;
            *ctx = &session->ctx;

            return i;
        }
    }

    return -1;
}

PRIVATE usStatus checkSessionID(uint8_t senderID, uint32_t sessionIndex)
{
    uint16_t expectedSessionID = SESSION_ID(senderID, sessionIndex);
    if (sessionIndex >= CFG_US_MAX_NUM_OF_SESSION)
    {
        return usStatus_InvalidSession;
    }

    UserSession* session = &settings.userSessions[sessionIndex];
    if (!session->flags.inUse || session->flags.sessionID != expectedSessionID)
    {
        return usStatus_InvalidSession;
    }

    return usStatus_Success;
}

PRIVATE void processRequest(uint8_t senderID, usRequestPackage* request)
{
    SysStatus retVal = SysStatus_Success;
    usResponsePackage response;
    uint32_t sequenceNo;
    struct AES_ctx* aes_ctx;
    usStatus status;

    response.header = request->header;
    response.header.status = usStatus_Success;

    switch (request->header.operation)
    {
        case usOp_init_ctx_iv:
            {
                if (settings.numOfSessions >= CFG_US_MAX_NUM_OF_SESSION)
                {
                    sendError(senderID, request->header.operation, usStatus_NoSessionSlotAvailable);
                    return;
                }

                uint32_t sessionID = getSessionID(senderID, &aes_ctx);
                AES_init_ctx_iv(aes_ctx, request->payload.init_ctx_iv.key, request->payload.init_ctx_iv.iv);

                {
                    response.payload.init_ctx_iv.ctx = (void*)sessionID;
                    (void)Sys_SendMessage(senderID, (uint8_t*)&response, sizeof(usResponsePackage), &sequenceNo);
                }
            }
            break;
        case usOp_deinit_ctx_iv:
            {
                uint32_t sessionIndex = (uint32_t)request->payload.deinit_ctx.ctx;

                status = checkSessionID(senderID, sessionIndex);
                if (status != usStatus_Success)
                {
                    sendError(senderID, request->header.operation, status);
                    return;
                }

                settings.userSessions[sessionIndex].flags.inUse = false;
                settings.numOfSessions--;
            }
            break;
        case usOp_cbc_enc:
        case usOp_cbc_dec:
            {
                uint32_t sessionIndex = (uint32_t)request->payload.cbc_enc_dec.ctx;

                status = checkSessionID(senderID, sessionIndex);
                if (status != usStatus_Success)
                {
                    sendError(senderID, request->header.operation, status);
                    return;
                }
                
                memcpy(response.payload.cbc_enc_dec.buf, request->payload.cbc_enc_dec.buf, AES_BLOCKLEN);

                if (request->header.operation == usOp_cbc_enc)
                {
                    AES_CBC_encrypt_buffer(&settings.userSessions[sessionIndex].ctx, response.payload.cbc_enc_dec.buf, AES_BLOCKLEN);
                }
                else
                {
                    AES_CBC_decrypt_buffer(&settings.userSessions[sessionIndex].ctx, response.payload.cbc_enc_dec.buf, AES_BLOCKLEN);
                }

                (void)Sys_SendMessage(senderID, (uint8_t*)&response, sizeof(usResponsePackage), &sequenceNo);
            }
            break;
        /* Unrecognised operation */
        default:
            sendError(senderID, response.header.operation, usStatus_InvalidOperation);
            break;
    }
}

PRIVATE void sendError(uint8_t receiverID, uint16_t operation, uint8_t status)
{
    uint32_t sequenceNo;
    (void)sequenceNo;
    usResponsePackage response =
    {
        .header.operation = operation,
        .header.status = status,
        .header.length = 0
    };

    (void)Sys_SendMessage(receiverID, (uint8_t*)&response, sizeof(response), &sequenceNo);
}
