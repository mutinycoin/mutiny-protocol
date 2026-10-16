#ifndef BUILD8_MINING_CONTROL_V2_H
#define BUILD8_MINING_CONTROL_V2_H
#include "work_v2.h"

/* Candidate application component. One task owns this object and all callbacks.
 * Initialize only from verified ACTIVE V2 enrollment and authenticated canonical
 * work context. Never initialize from an offered work envelope. Reinitialization
 * requires a new authenticated session; this object does not persist authority.
 * The existing V1 application/build fence is not changed by this component. */
typedef int (*build8_v2_monotonic_clock)(void *,uint64_t *);
typedef struct {
    build8_work_context context;
    build8_authorized_work work;
    uint8_t request_nonce[32];
    uint64_t last_clock,request_started,deadline,next_nonce,last_ticket;
    uint64_t effective_epoch,valid_until_height;
    bool initialized,run,session,accounting,request_pending,work_valid,clock_fault,job_live,maintenance;
} build8_mining_control_v2;

int build8_mining_v2_init(build8_mining_control_v2 *,const build8_work_context *,
    uint64_t,uint64_t,uint64_t);
void build8_mining_v2_run(build8_mining_control_v2 *,bool);
void build8_mining_v2_session(build8_mining_control_v2 *,bool);
/* Single owner enters BEFORE maintenance can mutate storage. This retires work
 * and the session but preserves RUN intent, accounting and the ticket floor.
 * Exit does not restore authority: a fresh authenticated session is required.
 * This is a control guard, not a replacement for the shared maintenance mutex. */
void build8_mining_v2_maintenance(build8_mining_control_v2 *,bool);
void build8_mining_v2_accounting(build8_mining_control_v2 *,bool);
void build8_mining_v2_retire(build8_mining_control_v2 *);
/* A request cannot replace another live request. The caller obtains fresh
 * nonzero nonces from qualified device entropy; no deterministic fallback. */
int build8_mining_v2_request(build8_mining_control_v2 *,const uint8_t[32],
    build8_v2_monotonic_clock,void *);
/* Lifetime is measured from device request START and capped at 60 seconds.
 * Real hybrid verification is mandatory. Clock is sampled again after it.
 * All input/workspace ranges must be disjoint from the control object. */
int build8_mining_v2_assign(build8_mining_control_v2 *,const uint8_t[32],uint64_t,
    uint64_t,const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,
    void *,size_t,build8_v2_monotonic_clock,void *);
/* Confirmed V2 channel plaintext only. Exact type5/version2 outer codec;
 * canonical parent/identity context remains independently pinned in control.
 * A false return requires owner-side connection retirement. */
int build8_mining_v2_offer(build8_mining_control_v2 *,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,
    build8_v2_monotonic_clock,void *);
int build8_mining_v2_nonce(build8_mining_control_v2 *,build8_v2_monotonic_clock,
    void *,uint64_t *);
/* After the hash loop found a solution, before queuing/signing it: recheck
 * authority, issued nonce and clock, copy public work, enter pending accounting
 * and retire mining atomically under the single-task ownership rule. This does
 * not verify PoW or create a receipt/finality claim. Last inclusive nonce works.
 * A failed call never exposes work or changes the caller's output. */
int build8_mining_v2_found(build8_mining_control_v2 *,const uint8_t[32],uint64_t,
    build8_v2_monotonic_clock,void *,build8_authorized_work *);
#endif
