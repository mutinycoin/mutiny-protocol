/* Status snapshot for the LoRa bridge OLED and its text layout.
 *
 * The bridge publishes a snapshot; the display task renders it. Every field
 * carries its own "known" flag so a value the firmware has not measured is
 * shown as "--", never as zero. Pure C, host-testable. */
#ifndef LORA_DISPLAY_MODEL_H
#define LORA_DISPLAY_MODEL_H

#include <stdbool.h>
#include <stdint.h>

#define LORA_DISPLAY_COLS 21  /* 128 px / 6 px per glyph */
#define LORA_DISPLAY_ROWS 8   /* 64 px / 8 px per row */

typedef enum {
    LORA_RADIO_UNKNOWN = 0,   /* not yet initialised */
    LORA_RADIO_OK,
    LORA_RADIO_FAULT,
} lora_radio_state_t;

typedef struct {
    lora_radio_state_t radio;
    bool armed;
    bool fem_fault;

    uint32_t tx_count, tx_limit;
    uint64_t airtime_ms;

    bool rx_known;
    uint32_t rx_count, rx_errors;

    bool last_rx_known;       /* set once a packet has been received this boot */
    int16_t last_rssi_dbm;
    int8_t last_snr_db;

    uint64_t uptime_s;
    uint8_t mac[6];
    bool mac_known;
} lora_display_status_t;

typedef struct {
    char line[LORA_DISPLAY_ROWS][LORA_DISPLAY_COLS + 1];
} lora_display_text_t;

/* Short status word for the bottom row: STARTING, FEM FAULT, RADIO FAULT,
 * TX ARMED or LISTENING. A fault always wins over armed. */
const char *lora_display_status_word(const lora_display_status_t *s);

/* stale: the display task has not received a snapshot within its window. */
void lora_display_layout(const lora_display_status_t *s, bool stale, lora_display_text_t *out);

#endif
