#ifndef BUILD8_QUAL_EVP_H
#define BUILD8_QUAL_EVP_H
#include <openssl/e_os2.h>
typedef struct build8_qual_md_ctx EVP_MD_CTX;
typedef struct build8_qual_md EVP_MD;
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);
EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *,const char *,const char *);
void EVP_MD_free(EVP_MD *);
int EVP_DigestInit_ex(EVP_MD_CTX *,const EVP_MD *,void *);
int EVP_DigestUpdate(EVP_MD_CTX *,const void *,size_t);
int EVP_DigestFinalXOF(EVP_MD_CTX *,unsigned char *,size_t);
#endif
