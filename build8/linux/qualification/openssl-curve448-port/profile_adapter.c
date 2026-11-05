/* Pinned Build8 qualification boundary; curve arithmetic remains upstream. */
#include "ed448.h"
#include <openssl/crypto.h>
#include <stdint.h>
#include <stddef.h>
extern int ossl_ed448_verify(OSSL_LIB_CTX *,const uint8_t *,size_t,const uint8_t *,const uint8_t *,const uint8_t *,size_t,uint8_t,const char *);

/* Reject malformed encodings and points annihilated by the upstream isogeny.
 * This is a protocol key-admission restriction, not an upstream RFC defect.
 */
int build8_qual_ed448_public_valid(const uint8_t *public_key,size_t length) {
    curve448_point_t point;
    if(!public_key || length!=57)return 0;
    int ok=ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(point,public_key)==C448_SUCCESS;
    if(ok)ok=!ossl_curve448_point_eq(point,ossl_curve448_point_identity);
    ossl_curve448_point_destroy(point);
    return ok;
}
int build8_qual_ed448_verify(const uint8_t *public_key,size_t public_length,
    const uint8_t *signature,size_t signature_length,const uint8_t *intent,size_t intent_length) {
    if(!signature || signature_length!=114 || !intent || intent_length!=64
        || !build8_qual_ed448_public_valid(public_key,public_length)
        || !build8_qual_ed448_public_valid(signature,57))return 0;
    return ossl_ed448_verify(NULL,intent,intent_length,signature,public_key,NULL,0,0,NULL)==1;
}
