#ifndef BUILD8_ASSIGNMENT_JOURNAL_V2_H
#define BUILD8_ASSIGNMENT_JOURNAL_V2_H
#include "enrollment_v2.h"
#define BUILD8_V2_ASSIGNMENT_BYTES_MAX 8192u
#define BUILD8_V2_JOURNAL_SLOTS_MAX 32u
/* PUBLIC storage only. Exact existing kind10 bytes, no private envelope change.
 * Caller serializes every operation. read/read_marker: 1 present, 0 absent,
 * -1 fault. append/append_marker must be absent-only, atomic and durably committed
 * before success, with failed/partial bytes preserved. A failure MAY have written
 * complete bytes; it never permits replacement. No automatic pruning/migration.
 * Backend protects local files/keys and bounds capacity, not the packet sender.
 * Physical crash/rollback/storage qualification is outside this interface. */
typedef struct {
    void *context;size_t slots;
    int (*read)(void *,size_t,uint8_t *,size_t,size_t *);
    int (*append)(void *,size_t,const uint8_t *,size_t);
    int (*read_marker)(void *,size_t,uint8_t *,size_t,size_t *);
    int (*append_marker)(void *,size_t,const uint8_t *,size_t);
} build8_v2_assignment_journal;
/* Trusted LOCAL own-chain adapter only; no incoming packet may supply callbacks.
 * candidate: current parent owner/Node/next generation/window AND never-active
 * Worker history permit this exact unsigned candidate. active: exact own verified
 * canonical due assignment/current authority for work height/epoch. Only ==1
 * accepts; denial/fault refuse. These checks are repeated around slow crypto,
 * durable publication and session signing. A local marker/ID is not authority. */
typedef struct {
    void *context;
    int (*candidate)(void *,const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
    int (*active)(void *,const uint8_t *,size_t,uint64_t,uint64_t);
} build8_v2_assignment_authority;
enum {
    BUILD8_V2_JOURNAL_FAULT=-1,BUILD8_V2_JOURNAL_CONFLICT=-2,
    BUILD8_V2_JOURNAL_FULL=-3,BUILD8_V2_JOURNAL_DENIED=-4,
    BUILD8_V2_JOURNAL_NOT_FOUND=0,BUILD8_V2_JOURNAL_STORED=1,
    BUILD8_V2_JOURNAL_PENDING=2,BUILD8_V2_JOURNAL_ACTIVE=3
};
/* Verified slices borrow the caller's exact public raw buffer. Signature and
 * Node descriptor checks run before success. ID is the existing unsigned
 * assignment ID domain (PROPOSED-UNFROZEN), not a new or frozen domain. */
typedef struct {
    const uint8_t *enrollment,*unsigned_binding,*owner,*node;
    size_t enrollment_length,unsigned_length,owner_length,node_length;
    build8_enrollment_v2_context context;
    uint8_t worker[57],id[32];
} build8_v2_assignment_view;
int build8_v2_assignment_view_verify(const uint8_t *,size_t,build8_v2_domain_hash,
    build8_v2_domain_hash,void *,size_t,build8_v2_assignment_view *);
/* STORED is only a durable exact-wire receipt. Exact duplicates remain
 * idempotent even after cancellation/expiry; only restore/activation may return
 * ACTIVE after current canonical checks. New rows require candidate eligibility. */
int build8_v2_assignment_journal_put(const build8_v2_assignment_journal *,const build8_v2_assignment_authority *,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t[32]);
int build8_v2_assignment_journal_activate(const build8_v2_assignment_journal *,const build8_v2_assignment_authority *,
    const uint8_t[32],const build8_enrollment_v2_context *,uint64_t,uint64_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
int build8_v2_assignment_journal_restore(const build8_v2_assignment_journal *,const build8_v2_assignment_authority *,
    const uint8_t[32],const build8_enrollment_v2_context *,uint64_t,uint64_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t *,size_t,size_t *);
#endif
