#ifndef BUILD8_ENROLLMENT_V2_STORE_H
#define BUILD8_ENROLLMENT_V2_STORE_H
#include "enrollment_v2.h"
/* This layer selects public enrollment authority after a separate immutable,
 * device-private candidate has been durably restored. It never stores a seed.
 * Caller serializes the entire operation and supplies that candidate's context.
 * Reads return 1 present, 0 absent, -1 fault; lengths must be bounded.
 * Writes must commit before success. Error may still mean a completed write.
 * Key 0: local compact signed-binding record. It omits only the unsigned body
 * already present in the immutable private candidate. Restore reconstructs the
 * EXACT canonical wire binding before all signatures and marker verification.
 * No automatic old-storage migration; V2 production has not been activated.
 * Key 1: activation marker over full wire bytes. Never any V1 key. */
#define BUILD8_V2_STORED_BINDING_BYTES 1523u
typedef int (*build8_v2_read)(void *,unsigned,uint8_t *,size_t,size_t *);
typedef int (*build8_v2_write)(void *,unsigned,const uint8_t *,size_t);
typedef struct {void *context;build8_v2_read read;build8_v2_write write;} build8_v2_store;
enum {BUILD8_V2_FAULT=-1,BUILD8_V2_PENDING=0,BUILD8_V2_ACTIVE=1};
int build8_v2_restore(const build8_v2_store *,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
int build8_v2_activate(const build8_v2_store *,const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
/* Explicit ordinary assignment path. SAME compact public record/marker format.
 * expected and owner MUST come from the independently current canonical binding
 * and local immutable candidate, never an incoming envelope. ACTIVE here is a
 * durable local signature marker, NOT proof of canonical inclusion/activation.
 * Canonical authority is rechecked by the trusted runtime on every session use.
 * These functions do not overwrite a different/corrupt published binding. */
int build8_v2_assignment_restore(const build8_v2_store *,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
int build8_v2_assignment_activate(const build8_v2_store *,const uint8_t *,size_t,const uint8_t *,size_t,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t);
#endif
