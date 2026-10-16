#ifndef BUILD8_WORKER_ACCOUNTING_V2_H
#define BUILD8_WORKER_ACCOUNTING_V2_H
#include "mining_control_v2.h"
#include "observation_store_v2.h"
/* Single task owns this actor, controller, backend and all calls. No reentrancy.
 * Zero initialize once at boot, then init from verified ACTIVE enrollment.
 * Never reinitialize to recover from a storage/session fault. RAM-held work must
 * survive STOP, disconnect, rekey and maintenance attempts within this boot.
 * Power loss before a successful durable flush can still lose volatile work.
 * This component does not initialize storage or grant network/PoW authority. */
typedef struct {
    build8_observation_scope_v2 scope;
    uint8_t pending[544],coordinator[32];
    uint16_t pending_length;
    bool initialized;
} build8_worker_accounting_v2;
int build8_worker_accounting_v2_init(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const build8_observation_scope_v2 *);
/* Restore ordinary startup state, or retry an uncertain write. Failure retires
 * mining and keeps accounting blocked. Only success may clear RAM-held work. */
int build8_worker_accounting_v2_sync(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const build8_observation_store_v2 *,build8_v2_domain_hash);
/* Atomic local capture only: no storage I/O. Success means retained in RAM, NOT
 * durably accepted. Caller must sync before transmission. Uses existing exact
 * PoW encoder and checks issued nonce/authority/deadline through the controller. */
int build8_worker_accounting_v2_found(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const uint8_t[32],uint64_t,build8_v2_monotonic_clock,void *);
/* Confirmed-channel plaintext codecs. Backend and all buffers must be disjoint.
 * Network owner must still enforce current session/context and write deadline. */
int build8_worker_accounting_v2_request(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const build8_observation_store_v2 *,build8_v2_domain_hash,
    const uint8_t[32],build8_v2_monotonic_clock,void *,uint8_t[73]);
int build8_worker_accounting_v2_submission(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const build8_observation_store_v2 *,build8_v2_domain_hash,
    uint8_t *,size_t,size_t *);
int build8_worker_accounting_v2_receipt(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const build8_observation_store_v2 *,
    const uint8_t *,size_t,const uint8_t *,size_t,build8_v2_domain_hash,
    build8_v2_domain_hash,void *,size_t);
/* Exact type4/version2/BE-u16 descriptor length/public descriptor/1672-byte
 * receipt wrapper. The descriptor is UNTRUSTED: identity must match the stored
 * pending coordinator and both signatures must pass. No authority adoption. */
int build8_worker_accounting_v2_receipt_packet(build8_worker_accounting_v2 *,
    build8_mining_control_v2 *,const build8_observation_store_v2 *,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
#endif
