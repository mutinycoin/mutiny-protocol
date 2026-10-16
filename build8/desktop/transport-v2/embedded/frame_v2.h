#ifndef BUILD8_EMBEDDED_FRAME_V2_H
#define BUILD8_EMBEDDED_FRAME_V2_H
#include <stddef.h>
#include <stdint.h>

/* Qualification candidate, not a production session-establishment API.
 * Storage is caller-owned, suitably aligned, memory-only and never copied or
 * serialized during use. Initialize only from a fresh authenticated handshake.
 * Reconnection/reboot MUST perform a new handshake. No hardware driver here. */
#define B8_FRAME_PAYLOAD 140u
#define B8_FRAME_HEADER 99u
#define B8_FRAME_MAX 255u
#define B8_FRAME_OBJECTS 256u
enum b8_frame_result { B8_FRAME_OK=0, B8_FRAME_ENCODING=1,
    B8_FRAME_CONTEXT=2, B8_FRAME_CRYPTO=3, B8_FRAME_EXPIRED=4,
    B8_FRAME_REPLAY=5, B8_FRAME_LIMIT=6 };
typedef struct {
    uint8_t kind, object[32];
    uint16_t fragment, count;
    uint8_t hops;
} b8_frame_metadata;

/* Trusted crypto provider, not a boolean supplied by untrusted callers.
 * Must authenticate ChaCha20-Poly1305 with the supplied nonce and exact AAD.
 * Return 1 ONLY on full authentication, otherwise 0. May write provisional
 * plaintext to the supplied private scratch buffer; caller will wipe it.
 * Must not retain pointers, reenter, or alter session storage. */
typedef int (*b8_frame_open_aead)(void *provider, const uint8_t nonce[12],
    const uint8_t aad[99], const uint8_t *ciphertext_with_tag,
    size_t ciphertext_length, uint8_t *plaintext);

typedef struct {
    uint8_t tag[16], id[32], rx_prefix[4], direction;
    uint64_t started_ms, highest, seen_low, seen_high, rx_bytes, rx_frames;
    uint16_t object_count;
    uint8_t objects[B8_FRAME_OBJECTS][32];
    uint32_t initialized;
} b8_frame_receiver;

int b8_frame_receiver_init(b8_frame_receiver *s, const uint8_t tag[16],
    const uint8_t id[32], const uint8_t rx_prefix[4], uint8_t local_direction,
    uint64_t now_ms);
void b8_frame_receiver_clear(b8_frame_receiver *s);
/* Exact-sized metadata/output buffers must not alias input or session storage.
 * Output buffers are cleared on every failure; receive state changes only after
 * authentication. now_ms must be monotonic time in a non-wrapping u64 domain. */
int b8_frame_receive(b8_frame_receiver *s, uint64_t now_ms,
    const uint8_t *frame, size_t length, b8_frame_open_aead authenticate,
    void *provider, b8_frame_metadata *metadata,
    uint8_t plaintext[140], size_t *plaintext_length);
size_t b8_frame_receiver_size(void);
size_t b8_frame_receiver_alignment(void);

typedef int (*b8_frame_seal_aead)(void *provider, const uint8_t nonce[12],
    const uint8_t aad[99], const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext_with_tag);
typedef struct {
    uint8_t tag[16], id[32], tx_prefix[4], direction;
    uint64_t started_ms, next, tx_bytes;
    uint16_t object_count;
    uint8_t objects[B8_FRAME_OBJECTS][32];
    uint32_t initialized;
} b8_frame_sender;
int b8_frame_sender_init(b8_frame_sender *s, const uint8_t tag[16],
    const uint8_t id[32], const uint8_t tx_prefix[4], uint8_t local_direction,
    uint64_t now_ms);
void b8_frame_sender_clear(b8_frame_sender *s);
/* Output must not alias session/metadata/input. Crypto failures consume the
 * reserved sequence and resource budget; a nonce is never reused after failure.
 * No persistent session import/export is provided. */
int b8_frame_seal(b8_frame_sender *s, uint64_t now_ms,
    const b8_frame_metadata *metadata, const uint8_t *plaintext, size_t length,
    b8_frame_seal_aead encrypt, void *provider, uint8_t frame[255],
    size_t *frame_length);
size_t b8_frame_sender_size(void);
size_t b8_frame_sender_alignment(void);
#endif
