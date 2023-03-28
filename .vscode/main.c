#include <stdio.h>
#include "mbedtls/sha256.h"

int main()
{
    unsigned char digest[32]; // 32-byte buffer to hold the hash result
    const char *str = "test";
    mbedtls_sha256((const unsigned char *)str, 4, digest, 0); // hash the string "test"

    // print the hash result
    printf("Hash of \"%s\":\n", str);
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}