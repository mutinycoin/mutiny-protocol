#ifndef BUILD8_WORKER_RUNTIME_GUARD_V2_H
#define BUILD8_WORKER_RUNTIME_GUARD_V2_H
#include "worker_connection_v2.h"
#include "mining_control_v2.h"
/* Same owner task as both objects. Invoke before mining/request/solution
 * handling and on every disconnect, maintenance and canonical-authority event.
 * Mining control must already be initialized from independently authenticated
 * canonical work context matching this enrollment/session. This guard never
 * initializes work context or treats a transport message as canonical state. */
/* Return 1 means a current authenticated session, not permission to hash:
 * RUN, accounting, work authorization, nonce and work deadline checks still
 * apply. A mismatched work height retires mining until the owner supplies a
 * newly authenticated work context; the guard never rewrites that context. */
int build8_worker_runtime_guard_v2(build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const uint8_t [64],uint64_t,uint64_t,uint64_t,bool);
/* Explicit disconnect/revocation: retire work before clearing session secrets.
 * Preserve RUN intent, pending accounting and ticket floor for reconciliation. */
void build8_worker_runtime_close_v2(build8_worker_connection_v2 *,build8_mining_control_v2 *);
/* On confirmation and before using a changed local authority/work context:
 * derive the exact session ID from current trusted enrollment and public key,
 * and require the mining binding to match it. Inputs are trusted local,
 * mutually disjoint, stable for this call; never use an incoming work offer as
 * its own context. This validates identity linkage, not parent/job finality.
 * Failure closes the session and retires mining. Does not initialize mining or
 * change its context/ticket floor. Use the cheaper guard above between events. */
int build8_worker_runtime_binding_v2(build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const build8_worker_local_v2 *,const uint8_t[57],uint64_t,uint64_t,uint64_t,bool);

/* Explicit journal mode: rederive Worker/session from immutable birth record,
 * full public journal and own CURRENT exact canonical record for EVERY use.
 * Same owner-task/disjoint stable objects; closes and retires on denial.
 * This is mandatory between events, not a cheaper cached-authority path. */
int build8_worker_runtime_journal_binding_v2(build8_worker_connection_v2 *,build8_mining_control_v2 *,
    const build8_worker_journal_local_v2 *,uint64_t,uint64_t,uint64_t,bool);
#endif
