/*
 * @file us_Internal.h
 *
 * @brief Microservice Internal Definitions
 *
 ******************************************************************************/

#ifndef __US_INTERNAL_H
#define __US_INTERNAL_H

/********************************* INCLUDES ***********************************/

#include "uService.h"

/***************************** MACRO DEFINITIONS ******************************/

#define MAX_AES_KEYLEN  32  // AES-256
#define AES_BLOCKLEN    16  // Block length in bytes - AES is 128b block only


/***************************** TYPE DEFINITIONS *******************************/

typedef enum
{
    usOp_init_ctx_iv,
    usOp_deinit_ctx_iv,
    usOp_cbc_enc,
    usOp_cbc_dec,
} usOperations;

typedef struct
{
    uServicePackageHeader header;

    union
    {
        struct
        {
            uint8_t key[MAX_AES_KEYLEN];
            uint8_t iv[AES_BLOCKLEN];
        } init_ctx_iv;
        struct
        {
            void* ctx;
        } deinit_ctx;
        struct
        {
            void* ctx;
            uint8_t buf[AES_BLOCKLEN];
        } cbc_enc_dec;
    } payload;
} usRequestPackage;

typedef struct
{
    uServicePackageHeader header;

    union
    {

        struct
        {
            void* ctx;
        } init_ctx_iv;
        struct
        {
            uint8_t buf[AES_BLOCKLEN];
        } cbc_enc_dec;
    } payload;
} usResponsePackage;

/**************************** FUNCTION PROTOTYPES *****************************/

/******************************** VARIABLES ***********************************/

#endif /* __US_INTERNAL_H */
