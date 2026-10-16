#ifndef BUILD8_EMBEDDED_KDF_CONFIG_V1_H
#define BUILD8_EMBEDDED_KDF_CONFIG_V1_H
#include <stddef.h>
#include "kdf_namespace_v1.h"
/* Isolated candidate: portable SHA-512/HMAC/HKDF only, no OS allocator/RNG/PSA. */
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA512_SMALLER
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO b8_kdf_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO b8_kdf_free
void *b8_kdf_calloc(size_t,size_t);
void b8_kdf_free(void *);
#endif
