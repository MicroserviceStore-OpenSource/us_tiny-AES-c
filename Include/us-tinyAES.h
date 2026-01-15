/*
 * @file us.h
 *
 * @brief Microservice Public API
 *
 ******************************************************************************/

#ifndef __US_TINYAES_H
#define __US_TINYAES_H

/********************************* INCLUDES ***********************************/

#include "uService.h"

/***************************** MACRO DEFINITIONS ******************************/

/***************************** TYPE DEFINITIONS *******************************/

/*
 * Default Status
 */
typedef enum
{
    usStatus_Success = 0,
    /* Operation not defined or the access not granted */
    usStatus_InvalidOperation,
    /* Timeout occurred during the opereration */
    usStatus_Timeout,
    /* Microservice does not have any available session */
    usStatus_NoSessionSlotAvailable,
    /* Request to an invalid session */
    usStatus_InvalidSession,
    /* Invalid Parameter - Insufficient Input or Output Size  */
    usStatus_InvalidParam_UnsufficientSize,
    /* Invalid Parameter - Input or Output exceeds the allowed capacity  */
    usStatus_InvalidParam_SizeExceedAllowed,

    /* The developer can defines custom statuses */
    usStatus_CustomStart = 32
} usStatus;

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

struct us_tinyAES_ctx
{
    void* ctx;
};

/**************************** FUNCTION PROTOTYPES *****************************/

/******************************** VARIABLES ***********************************/

/**************************** PUBLIC FUNCTIONS ********************************/
/*
 * Initialise the Microservice
 *
 * @param none
 *
 * @retval SysStatus_Success Success
 * @retval SysStatus_NotFound The Microservice not found on the device.
 */
SysStatus us_TINYAES_Initialise(void);

void us_tinyAES_init_ctx_iv(struct us_tinyAES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

// We added this function to release the session
void us_tinyAES_deinit_ctx(struct us_tinyAES_ctx* ctx);

// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void us_tinyAES_CBC_encrypt_buffer(struct us_tinyAES_ctx* ctx, uint8_t* buf, size_t length);
void us_tinyAES_CBC_decrypt_buffer(struct us_tinyAES_ctx* ctx, uint8_t* buf, size_t length);

#endif /* __US_TINYAES_H */
