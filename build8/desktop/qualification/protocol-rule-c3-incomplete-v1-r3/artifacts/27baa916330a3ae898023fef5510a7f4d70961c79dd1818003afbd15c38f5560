#ifndef BUILD8_HANDSHAKE_FRAMES_V2_H
#define BUILD8_HANDSHAKE_FRAMES_V2_H
#include "frame_v2.h"
#define B8_HANDSHAKE_MAX_MESSAGE 3050u
#define B8_HANDSHAKE_MAX_PEERS 64u
#define B8_HANDSHAKE_MAX_FLIGHTS 4u
/* Entirely untrusted PUBLIC handshake messages, never private key material.
 * Successful reassembly conveys ZERO peer authentication or session authority.
 * The pinned hybrid handshake and Finished checks are still mandatory. */
typedef struct {
    uint8_t active,kind,peer[32],id[16];
    uint64_t started_ms;
    uint32_t received;
    uint8_t message[B8_HANDSHAKE_MAX_MESSAGE];
} b8_handshake_flight;
typedef struct {
    uint8_t tag[16], peers[B8_HANDSHAKE_MAX_PEERS][32];
    uint16_t peer_count;
    b8_handshake_flight flights[B8_HANDSHAKE_MAX_FLIGHTS];
    uint32_t initialized;
} b8_handshake_reassembler;
size_t b8_handshake_size(void);
size_t b8_handshake_alignment(void);
void b8_handshake_clear(b8_handshake_reassembler *s);
int b8_handshake_init(b8_handshake_reassembler *s,const uint8_t tag[16],
    const uint8_t *peers,size_t peer_count);
void b8_handshake_expire(b8_handshake_reassembler *s,uint64_t now_ms);
size_t b8_handshake_pending(const b8_handshake_reassembler *s);
/* Buffers/state must not alias. Output len=0 means an incomplete flight, not
 * authentication. expected_kind is set by the caller's handshake state machine.
 * One flight per pinned peer; conflicting input never replaces it or extends
 * its deadline. Expiry is processed before untrusted parsing, as in Rust. */
int b8_handshake_receive(b8_handshake_reassembler *s,uint64_t now_ms,
    uint8_t expected_kind,const uint8_t *frame,size_t frame_length,
    uint8_t peer[32],uint8_t message[3050],size_t *message_length);
/* flight_id is a fresh PUBLIC nonce supplied by the trusted local CSPRNG. It is
 * not an AEAD nonce or authentication proof. No randomness fallback exists. */
int b8_handshake_fragment(const uint8_t tag[16],const uint8_t peer[32],
    const uint8_t flight_id[16],uint8_t kind,const uint8_t *message,size_t length,
    uint8_t index,uint8_t out[255],size_t *out_length);
#endif
