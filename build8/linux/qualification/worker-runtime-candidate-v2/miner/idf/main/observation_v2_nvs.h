#ifndef BUILD8_OBSERVATION_V2_NVS_H
#define BUILD8_OBSERVATION_V2_NVS_H
#include "observation_store_v2.h"
/* Candidate V2 adapter; not linked into the installed V1 application.
 * The caller must own the existing maintenance mutex for the whole operation,
 * including obtaining the trusted scope from verified ACTIVE V2 enrollment.
 * Do not derive that scope or the pending coordinator from incoming receipts.
 * NVS must already be initialized; this adapter never initializes/erases it.
 * No ISR use, automatic reset, namespace migration, or anti-rollback claim. */
int build8_observation_v2_nvs_provision(const build8_observation_scope_v2 *,build8_v2_domain_hash);
int build8_observation_v2_nvs_restore(const build8_observation_scope_v2 *,build8_v2_domain_hash,build8_observation_state_v2 *);
/* For the single owner accounting pipeline. Returns NULL without the existing
 * maintenance lease; every callback rechecks ownership. Never retain a lease
 * merely by retaining this pointer. */
const build8_observation_store_v2 *build8_observation_v2_nvs_backend(void);
/* After retiring session/work, with no pending observation: durably preserve
 * the authenticated local checkpoint before reclaiming its redundant full
 * slots. Hold maintenance ownership until update/rotation and retired-policy
 * cleanup finish. Resume only with fresh accounted work. No counters reset. */
int build8_observation_v2_nvs_park(const build8_observation_scope_v2 *,build8_v2_domain_hash);
int build8_observation_v2_nvs_queue(const build8_observation_scope_v2 *,const uint8_t *,size_t,const uint8_t[32],build8_v2_domain_hash);
int build8_observation_v2_nvs_receipt(const build8_observation_scope_v2 *,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
#endif
