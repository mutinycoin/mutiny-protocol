#ifndef BUILD8_WORKER_SESSION_AUTH_V2_H
#define BUILD8_WORKER_SESSION_AUTH_V2_H
#include "enrollment_v2.h"
#define BUILD8_WORKER_HELLO_V2_LENGTH 1722
#define BUILD8_WORKER_RESPONSE_V2_LENGTH 3050
/* Public bounded authentication candidate only. Context and Worker public key
 * must come from current verified ACTIVE enrollment. Descriptor identity must
 * match its pinned coordinator. Does not establish shared keys or a session.
 * All input/output/workspace ranges are caller-owned and must be disjoint.
 * h512 must support public inputs up to 3378 bytes (bounded release adapter).
 * No private operation, storage, RNG, RF, allocation or key agreement here. */
int build8_worker_session_context_v2(const build8_enrollment_v2_context *,const uint8_t [57],
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,uint8_t [64]);
/* Exact response = body1656 || Ed448114 || FNDSA1280. Returns the authenticated
 * transcript only after BOTH Node signatures pass. Caller must also bind the
 * hello to its own pending ephemeral state and enforce the handshake deadline. */
int build8_worker_session_verify_node_v2(const build8_enrollment_v2_context *,const uint8_t [57],
    const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t [64]);
#endif
