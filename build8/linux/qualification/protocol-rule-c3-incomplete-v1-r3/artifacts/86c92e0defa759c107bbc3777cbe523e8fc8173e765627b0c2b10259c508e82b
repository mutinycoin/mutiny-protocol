/* Qualification platform shim, not an OpenSSL public-header replacement. */
#ifndef BUILD8_QUAL_E_OS2_H
#define BUILD8_QUAL_E_OS2_H
#include <stdint.h>
#include <stddef.h>
#ifdef _MSC_VER
#define ossl_inline __inline
#define __owur
#else
#define ossl_inline inline
#define __owur __attribute__((warn_unused_result))
#endif
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
#endif
