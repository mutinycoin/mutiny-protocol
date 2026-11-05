#ifndef BUILD8_OBJECT_CONTROL_V2_H
#define BUILD8_OBJECT_CONTROL_V2_H
#include "frame_v2.h"
/* Public control codecs only. Parse only authenticated session plaintext.
 * Delivery controls confer no transaction, settlement or voting authority.
 * All output buffers must be exact-sized and disjoint from every input.
 * Return 0 on success; clear all outputs on failure. No heap or storage I/O. */
#define B8_OBJECT_MAX_BYTES 2097152u
#define B8_OBJECT_BITMAP_BITS 1080u
typedef struct { uint16_t start, count; uint8_t packed[135]; } b8_object_bitmap;
int b8_object_offer_parse(const b8_frame_metadata *metadata,
    const uint8_t *payload, size_t length, uint8_t *kind, uint32_t *object_length);
int b8_object_offer_encode(const uint8_t id[32], uint8_t kind,
    uint32_t object_length, uint8_t hops, b8_frame_metadata *metadata,
    uint8_t payload[6]);
int b8_object_bitmap_parse(const uint8_t *payload, size_t length,
    uint16_t total, b8_object_bitmap *bitmap);
int b8_object_bitmap_encode(const b8_object_bitmap *bitmap, uint16_t total,
    uint8_t payload[140], size_t *length);
#endif
