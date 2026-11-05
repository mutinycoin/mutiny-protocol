#ifndef BUILD8_ENROLLMENT_V2_H
#define BUILD8_ENROLLMENT_V2_H
#include <stddef.h>
#include <stdint.h>
/* Candidate verifier only. Caller supplies already trusted supervised/parent
 * context. Never use an incoming envelope as its own expected binding.
 * No key generation, storage, state transition or activation is performed. */
typedef int (*build8_v2_domain_hash)(const char *,const uint8_t *,size_t,uint8_t *);
typedef struct {
    uint8_t genesis[32],fingerprint[32],license[32],owner_descriptor[32];
    uint64_t owner_generation;
    uint8_t coordinator[32];
    uint64_t configuration_generation;
    uint8_t device_mac[6];
    uint64_t assignment_generation,effective_epoch,valid_until_height;
} build8_enrollment_v2_context;
/* Public identity derivation only, never enrollment/authorization. Trusted
 * local hash adapter; output and inputs must be disjoint. */
int build8_enrollment_v2_worker_id(const build8_enrollment_v2_context *,const uint8_t[57],
    build8_v2_domain_hash,uint8_t[32]);
int build8_enrollment_v2_unsigned(const build8_enrollment_v2_context *,const uint8_t[57],
    build8_v2_domain_hash,uint8_t *,size_t,size_t *);
/* Pending candidate self-check only. No owner authorization or mining authority.
 * public_key must be derived locally from the durably stored device-private seed. */
int build8_enrollment_v2_candidate_valid(const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t[57],const uint8_t[114],build8_v2_domain_hash,build8_v2_domain_hash);
/* Ordinary assignment possession self-check ONLY; it grants no owner/canonical
 * activation authority. The separate Genesis self-check remains strict. */
int build8_enrollment_v2_assignment_candidate_valid(const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t[57],const uint8_t[114],build8_v2_domain_hash,build8_v2_domain_hash);
int build8_enrollment_v2_verify(const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t *,size_t,int,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
/* Ordinary assignment only: positive activation epoch AND delivery deadline.
 * No fallback from failed Genesis validation and no canonical-state claim. */
int build8_enrollment_v2_assignment_context_valid(const uint8_t *,size_t,const uint8_t *,size_t,build8_v2_domain_hash);
int build8_enrollment_v2_assignment_verify(const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
/* Structural public decode/scope only; neither proves owner signatures or
 * canonical authority. Outputs and inputs must be disjoint caller buffers. */
int build8_enrollment_v2_assignment_decode(const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_enrollment_v2_context *,uint8_t[57]);
int build8_enrollment_v2_assignment_scope_matches(const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t *,size_t,const uint8_t *,size_t,build8_v2_domain_hash);
#endif
