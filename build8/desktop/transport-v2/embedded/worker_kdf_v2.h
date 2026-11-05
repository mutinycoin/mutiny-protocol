#ifndef BUILD8_WORKER_KDF_V2_H
#define BUILD8_WORKER_KDF_V2_H
#include <stdint.h>
/* Candidate only. Exact Worker V2 schedule, all input/output buffers disjoint.
 * No OS allocation: two fixed 256-byte slots under a nonblocking atomic guard.
 * Invalid/overlapping buffer ranges return 0 without touching caller storage.
 * Other failures clear output. The caller owns and must erase the input secrets.
 * Success is key derivation only, not authentication, Finished or activation. */
int b8_worker_kdf_v2(const uint8_t [56],const uint8_t [32],const uint8_t [64],uint8_t [104]);
#ifdef BUILD8_KDF_TESTS
/* Synthetic qualification only, excluded from ordinary builds. */
int b8_worker_kdf_test_fail_allocation(int);
int b8_worker_kdf_test_pool_clear(void);
#endif
#endif
