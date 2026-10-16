#ifndef BUILD8_FRAME_MBEDTLS_CONFIG_H
#define BUILD8_FRAME_MBEDTLS_CONFIG_H
#include "frame_namespace_v2.h"
/* Qualification-only portable subset; no TLS, RNG, PSA or hardware ALT path. */
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_SELF_TEST
#endif
