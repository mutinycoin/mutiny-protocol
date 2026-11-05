#include "lora_display_model.h"

#include <stdio.h>
#include <string.h>

const char *lora_display_status_word(const lora_display_status_t *s)
{
    if (!s || s->radio == LORA_RADIO_UNKNOWN) return "STARTING";
    if (s->fem_fault) return "FEM FAULT";
    if (s->radio == LORA_RADIO_FAULT) return "RADIO FAULT";
    if (s->armed) return "TX ARMED";
    return "DISARMED";
}

/* snprintf truncates to the row width; rows are always NUL-terminated. */
#define ROW(n, ...) snprintf(out->line[n], sizeof out->line[n], __VA_ARGS__)

void lora_display_layout(const lora_display_status_t *s, bool stale, lora_display_text_t *out)
{
    memset(out, 0, sizeof *out);
    ROW(0, "MUTINY LORA");

    if (!s) {
        ROW(7, "STATUS STARTING");
        return;
    }

    if (s->mac_known)
        ROW(1, "NODE %02X%02X%02X", s->mac[3], s->mac[4], s->mac[5]);
    else
        ROW(1, "NODE --");

    const char *radio = s->radio == LORA_RADIO_OK ? "OK" : s->radio == LORA_RADIO_FAULT ? "FAULT" : "--";
    ROW(2, "RADIO %s ARM %s", radio, s->armed ? "YES" : "NO");

    ROW(3, "TX %lu/%lu AIR %lluMS", (unsigned long)s->tx_count, (unsigned long)s->tx_limit,
        (unsigned long long)s->airtime_ms);

    if (s->rx_known)
        ROW(4, "RX %lu ERR %lu", (unsigned long)s->rx_count, (unsigned long)s->rx_errors);
    else
        ROW(4, "RX -- ERR --");

    if (s->last_rx_known)
        ROW(5, "RSSI %d SNR %d", (int)s->last_rssi_dbm, (int)s->last_snr_db);
    else
        ROW(5, "RSSI -- SNR --");

    uint64_t up = s->uptime_s;
    if (up >= 100ull * 3600ull)
        ROW(6, "UP %lluH", (unsigned long long)(up / 3600ull));
    else
        ROW(6, "UP %02u:%02u:%02u", (unsigned)(up / 3600ull), (unsigned)(up / 60ull % 60ull),
            (unsigned)(up % 60ull));

    ROW(7, "STATUS %s", stale ? "STALE" : lora_display_status_word(s));
}
