#include <iostream>
#include "AES_CBC.h"
#include "AES_ECB.h"
#include "AES.h"
#include <stdio.h>

void AES256_ECB()
{
    AES_ECB AES_ECB(AESKeyLength::AES256);
    uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    uint8_t right[] = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};

    uint8_t plain[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    unsigned int len = 0;
    uint8_t out[16];

    AES_ECB.AES_ECB_decript(right, out, key, len);

    printf("AES256 ECB test ... \n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", (unsigned char)out[i]);
    }

    if (0 == memcmp((char *)out, (char *)plain, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void AES192_ECB()
{
    AES_ECB AES_ECB(AESKeyLength::AES192);
    uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t right[] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};

    unsigned int len = 0;
    uint8_t out[16];

    AES_ECB.AES_ECB_decript(right, out, key, len);

    printf("AES192 ECB test ... \n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", (unsigned char)out[i]);
    }

    if (0 == memcmp((char *)out, (char *)plain, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void AES128_ECB()
{
    AES_ECB AES_ECB(AESKeyLength::AES128);
    uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t right[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    unsigned int len = 0;
    uint8_t out[16];

    AES_ECB.AES_ECB_decript(right, out, key, len);

    printf("AES128 ECB test ... \n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", (unsigned char)out[i]);
    }

    if (0 == memcmp((char *)out, (char *)plain, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void AES128_CBC()
{
    AES_CBC AES_CBC(AESKeyLength::AES128);
    uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t right[] = {0x58, 0xb6, 0x24, 0x13, 0x73, 0xc9, 0x68, 0x8f, 0xa8, 0x7e, 0x40, 0xad, 0x92, 0xb7, 0xa3, 0x1c};

    unsigned int len = 0;
    uint8_t out[16];

    uint8_t iv[] = {0xe1, 0x61, 0xf4, 0x80, 0x14, 0x1f, 0x74, 0x16, 0x12, 0x1d, 0x1c, 0x10, 0x13, 0x11, 0x18, 0x14};

    AES_CBC.AES_CBC_encript(right, out, key, len, iv);

    printf("AES128 CBC test ... \n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", (unsigned char)out[i]);
    }

    if (0 == memcmp((char *)out, (char *)plain, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void AES192_CBC()
{
    AES_CBC AES_CBC(AESKeyLength::AES192);
    uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t right[] = {0x29, 0x0c, 0x79, 0x4d, 0x19, 0xa5, 0x2e, 0x18, 0x5b, 0x98, 0x76, 0xa6, 0x41, 0x00, 0x2e, 0xbb};

    unsigned int len = 0;
    uint8_t out[16];
    uint8_t iv[] = {0xe1, 0x61, 0xf4, 0x80, 0x14, 0x1f, 0x74, 0x16, 0x12, 0x1d, 0x1c, 0x10, 0x13, 0x11, 0x18, 0x14};

    AES_CBC.AES_CBC_encript(right, out, key, len, iv);

    printf("AES192 CBC test ... \n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", (unsigned char)out[i]);
    }

    if (0 == memcmp((char *)out, (char *)plain, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void AES256_CBC()
{
    AES_CBC AES_CBC(AESKeyLength::AES256);
    uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    uint8_t right[] = {0x57, 0x83, 0xec, 0xeb, 0xd6, 0x88, 0x39, 0xf1, 0x30, 0xb1, 0x2a, 0xda, 0x85, 0x25, 0x39, 0x64};

    uint8_t plain[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    unsigned int len = 0;
    uint8_t out[16];

    uint8_t iv[] = {0xe1, 0x61, 0xf4, 0x80, 0x14, 0x1f, 0x74, 0x16, 0x12, 0x1d, 0x1c, 0x10, 0x13, 0x11, 0x18, 0x14};

    AES_CBC.AES_CBC_encript(right, out, key, len, iv);

    printf("AES256 CBC test ... \n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", (unsigned char)out[i]);
    }

    if (0 == memcmp((char *)out, (char *)plain, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

int main()
{
    AES256_ECB();
    AES192_ECB();
    AES128_ECB();
    AES128_CBC();
    AES192_CBC();
    AES256_CBC();
}