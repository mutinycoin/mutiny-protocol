#ifndef BUILD8_WORKER_V2_CANDIDATE_H
#define BUILD8_WORKER_V2_CANDIDATE_H
#include "enrollment_v2.h"
#include "enrollment_v2_store.h"
#include "assignment_journal_v2.h"
#define BUILD8_V2_PRIVATE_RECORD_MAX 2775
/* Trusted device-local backend only. No transport handler may supply callbacks.
 * read: 1 present, 0 absent, -1 failure. write success requires durable commit.
 * entropy success requires the qualified hardware CSPRNG prerequisite state.
 * Caller serializes calls and enables this only after final ceremony context.
 * There is deliberately no seed export, erase, overwrite or recovery API. */
typedef struct {
    void *context;
    int (*read)(void *,uint8_t *,size_t,size_t *);
    int (*write)(void *,const uint8_t *,size_t);
    int (*entropy)(void *,uint8_t *,size_t);
} build8_v2_private_backend;
typedef struct {
    uint8_t unsigned_binding[512],owner_descriptor[2048],worker_public[57],possession[114];
    size_t unsigned_length,owner_length;
} build8_v2_public_candidate;
int build8_v2_candidate_public(const build8_v2_private_backend *,build8_v2_domain_hash,build8_v2_domain_hash,build8_v2_public_candidate *);
int build8_v2_candidate_prepare(const build8_v2_private_backend *,const build8_enrollment_v2_context *,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,build8_v2_public_candidate *);
/* Explicit ordinary assignment creation/self-check, SAME immutable private
 * record layout/domain and absent-only durable creation. Context/descriptor are
 * independently reviewed trusted inputs; epoch/deadline must be positive.
 * Backend absence must also certify no orphaned public authority records.
 * No overwrite/recovery, no hardware entropy bypass, no canonical authority from
 * possession alone. Legacy Genesis APIs above remain strictly Genesis-shaped. */
int build8_v2_assignment_candidate_public(const build8_v2_private_backend *,build8_v2_domain_hash,
    build8_v2_domain_hash,build8_v2_public_candidate *);
int build8_v2_assignment_candidate_prepare(const build8_v2_private_backend *,const build8_enrollment_v2_context *,
    const uint8_t *,size_t,build8_v2_domain_hash,build8_v2_domain_hash,build8_v2_public_candidate *);
/* Trusted handshake adapter only: authenticate the pinned Node response before
 * calling. The transcript is the canonical Worker session transcript digest.
 * Caller serializes private/public storage and supplies current trusted binding,
 * height and epoch. No network handler may supply those authority inputs.
 * Requires genuinely verified ACTIVE owner authorization; pending is denied.
 * Fixed session domain only; no private export, entropy draw or storage writes.
 * Inputs, output and verification workspace must be separate caller buffers. */
int build8_v2_candidate_sign_session(const build8_v2_private_backend *,const build8_v2_store *,
    const build8_enrollment_v2_context *,uint64_t,uint64_t,const uint8_t [64],
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t [114]);
/* First ordinary assignment tranche: current canonical binding must equal the
 * exact immutable birth binding; public record/signatures are fully rechecked.
 * This does NOT yet support re-signing a missed delivery window/public journal. */
int build8_v2_assignment_candidate_sign_session(const build8_v2_private_backend *,const build8_v2_store *,
    const build8_enrollment_v2_context *,uint64_t,uint64_t,const uint8_t [64],
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t [114]);
/* PUBLIC journal successor. Re-prove only a durably existing ORDINARY birth;
 * no Genesis fallback, entropy, private write, seed export or arbitrary domain.
 * Current candidate/history checks come from the trusted own-chain provider.
 * Identity scope stays fixed; current owner/window/Node terms may be reviewed
 * afresh. Inputs/outputs are separate local caller buffers. */
int build8_v2_assignment_candidate_reprove(const build8_v2_private_backend *,const build8_v2_assignment_authority *,
    const build8_enrollment_v2_context *,const uint8_t *,size_t,const uint8_t *,size_t,
    build8_v2_domain_hash,build8_v2_domain_hash,build8_v2_public_candidate *);
int build8_v2_assignment_journal_current(const build8_v2_private_backend *,const build8_v2_assignment_journal *,
    const build8_v2_assignment_authority *,const build8_enrollment_v2_context *,const uint8_t *,size_t,
    uint64_t,uint64_t,build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t[57],uint8_t[64]);
int build8_v2_assignment_journal_sign_session(const build8_v2_private_backend *,const build8_v2_assignment_journal *,
    const build8_v2_assignment_authority *,const build8_enrollment_v2_context *,uint64_t,uint64_t,const uint8_t[64],
    build8_v2_domain_hash,build8_v2_domain_hash,void *,size_t,uint8_t[114]);
#endif
