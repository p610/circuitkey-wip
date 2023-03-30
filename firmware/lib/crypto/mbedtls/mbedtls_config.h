// Configure mbed TLS
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_DEPRECATED_REMOVED
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_NIST_OPTIM

#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

// Enable mbedtls modules
#define MBEDTLS_ECDH_C
#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C

#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_PLATFORM_C

#define MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE

// Memory allocation hooks
#include <stdlib.h>
#include <stdio.h>
void *m_tracked_calloc(size_t nmemb, size_t size);
void m_tracked_free(void *ptr);
#define MBEDTLS_PLATFORM_STD_CALLOC m_tracked_calloc
#define MBEDTLS_PLATFORM_STD_FREE m_tracked_free
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO snprintf

// Time hook
#include <time.h>
time_t rp2_rtctime_seconds(time_t *timer);
#define MBEDTLS_PLATFORM_TIME_MACRO rp2_rtctime_seconds

#include "mbedtls/check_config.h"
