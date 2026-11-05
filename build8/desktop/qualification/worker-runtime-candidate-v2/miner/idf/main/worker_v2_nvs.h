#ifndef BUILD8_WORKER_V2_NVS_H
#define BUILD8_WORKER_V2_NVS_H
#include "worker_v2_candidate.h"
#include "worker_handshake_v2.h"
/* Candidate V2-only application integration, not enabled in installed V1.
 * Init is single-task startup before Wi-Fi, ADC or I2S initialization. Call the
 * irreversible radio/peripheral latch before starting any of those subsystems. */
int build8_worker_v2_init_before_radio(void);
/* RF/ADC/I2S may start only after this returns 1; busy means defer startup. */
int build8_worker_v2_peripherals_started(void);
int build8_worker_v2_prepare(const build8_enrollment_v2_context *,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,build8_v2_public_candidate *);
int build8_worker_v2_public(build8_v2_domain_hash,build8_v2_domain_hash,build8_v2_public_candidate *);
int build8_worker_v2_activate(const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
int build8_worker_v2_status(build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
/* Trusted handshake task only, after authenticating the pinned Node response.
 * Current context/height/epoch come from trusted canonical authority, never a
 * raw network request. Serialized with enrollment, update and policy changes. */
int build8_worker_v2_sign_session(const build8_enrollment_v2_context *,uint64_t,uint64_t,
    const uint8_t [64],build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t [114]);
/* Trusted owner-task configuration only. Backend pointers in local must be
 * NULL: this adapter supplies its own private/public stores without exporting
 * them. All input/state/output ranges must be disjoint. Output is usable only
 * on return 1; busy/failure consumes pending state. Pass a fresh empty channel
 * to finish. Entropy/clock remain separately qualified platform callbacks. */
int build8_worker_v2_handshake_begin(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,uint8_t [1722]);
int build8_worker_v2_handshake_accept(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,const uint8_t *,size_t,uint8_t [130]);
int build8_worker_v2_handshake_finish(build8_worker_pending_v2 *,const build8_worker_local_v2 *,uint64_t,uint64_t,const uint8_t *,size_t,b8_worker_channel *);
#endif
