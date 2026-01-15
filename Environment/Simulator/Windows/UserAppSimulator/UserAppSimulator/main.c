
/* Enable all the log levels */
#define LOG_INFO_ENABLED        1
#define LOG_WARNING_ENABLED     1
#define LOG_ERROR_ENABLED       1
#include "SysCall.h"

#include "us-TINYAES.h"

#define CHECK_US_ERR(_sysStatus, _usStatus) \
                if (_sysStatus != SysStatus_Success || _usStatus != usStatus_Success) \
                { LOG_PRINTF(" > us Test Failed. Line %d. Sys Status %d | us Status %d. Exiting the User Application...", __LINE__, _sysStatus, _usStatus); Sys_Exit(); }

int main(void)
{
    SysStatus retVal;

    LOG_PRINTF(" > Container : Microservice Test User App");

    SYS_INITIALISE_IPC_MESSAGEBOX(retVal, 4);

    us_TINYAES_Initialise();

    {
        struct us_tinyAES_ctx ctx;
        uint8_t key[]   =  { 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
        uint8_t iv[]    =  { 0x39,0xF2,0x33,0x69,0xA9,0xD9,0xBA,0xCF,0xA5,0x30,0xE2,0x63,0x04,0x23,0x14,0x61 };
        uint8_t plain[] =  { 0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };  
        uint8_t cipher[] = { 0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b };

        uint8_t buffer[AES_BLOCKLEN];

        {
            us_tinyAES_init_ctx_iv(&ctx, key, iv);

            memcpy(buffer, plain, AES_BLOCKLEN);
            us_tinyAES_CBC_encrypt_buffer(&ctx, buffer, AES_BLOCKLEN);

            if (memcmp(buffer, cipher, AES_BLOCKLEN) != 0)
            {
                LOG_PRINTF(" > us Test Failed. Encrypted data mistmatch.");
                Sys_Exit();
            }
            us_tinyAES_deinit_ctx(&ctx);
        }
        
        {
            us_tinyAES_init_ctx_iv(&ctx, key, iv);

            us_tinyAES_CBC_decrypt_buffer(&ctx, buffer, AES_BLOCKLEN);
            if (memcmp(buffer, plain, AES_BLOCKLEN) != 0)
            {
                LOG_PRINTF(" > us Test Failed. Decrypted data mistmatch.");
                Sys_Exit();
            }

            us_tinyAES_deinit_ctx(&ctx);
        }

        LOG_PRINTF(" > us Test Success");
    }

    LOG_PRINTF(" > Exiting the User Application");
    /* Exit the Container */
    Sys_Exit();

    return 0;
}
