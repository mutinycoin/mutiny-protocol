#ifndef BUILD8_WORKER_MAINTENANCE_V2_H
#define BUILD8_WORKER_MAINTENANCE_V2_H
#include "worker_runtime_guard_v2.h"
#include "worker_accounting_v2.h"
/* Same owner task, live mutually disjoint objects and connection backing
 * buffers. Caller owns the existing maintenance mutex for this WHOLE call and
 * the ensuing verified update/rotation/cleanup. No automatic lock acquisition.
 * Retires work/session before storage I/O. Flushes any RAM-held result but
 * REFUSES maintenance while a result still awaits its genuine receipt.
 * Success means checkpoint parked, not firmware/policy authorization.
 * Failure leaves maintenance asserted and RUN/pending work preserved. Owner
 * unwinds/reconciles explicitly, then exits maintenance and obtains a new
 * authenticated session/accounted work. Never resume before maintenance
 * cleanup finishes; this function does not implement the complete task. */
int build8_worker_maintenance_v2_prepare(build8_worker_connection_v2 *,
    build8_worker_accounting_v2 *,build8_mining_control_v2 *,build8_v2_domain_hash);
#endif
