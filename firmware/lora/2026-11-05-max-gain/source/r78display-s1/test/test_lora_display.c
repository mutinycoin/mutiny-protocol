/* Host tests for the pure-C parts of the LoRa status display. */
#include <stdio.h>
#include <string.h>

#include "lora_display_model.h"
#include "lora_display_profile.h"
#include "mono_fb.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(a, b) do { checks++; if (strcmp((a), (b))) { failures++; printf("FAIL %s:%d \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); } } while (0)

/* V4.3 documented pins (schematic + pin map) and Vext low = on. The address
 * and controller are NOT measured: the shipped profile leaves them unset. */
static lora_display_profile_t v43_documented(void)
{
    lora_display_profile_t p = {17, 18, 21, 36, 0, -1, 0};
    return p;
}

/* The documented pins plus the two facts still to be confirmed on a panel. */
static lora_display_profile_t lead_profile(void)
{
    lora_display_profile_t p = v43_documented();
    p.i2c_addr = 0x3C;
    p.controller_selected = 1;
    return p;
}

static void test_profile(void)
{
    lora_display_profile_t unset = {-1, -1, -1, -1, -1, -1, 0};
    CHECK(lora_display_profile_check(&unset) == LORA_DISPLAY_PROFILE_UNSET);
    CHECK(lora_display_profile_check(NULL) == LORA_DISPLAY_PROFILE_UNSET);

    /* As shipped for V4.3: still refuses, because the address is unmeasured. */
    lora_display_profile_t p = v43_documented();
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_UNSET);
    p.i2c_addr = 0x3C;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_CONTROLLER_UNCONFIRMED);
    CHECK_STR(lora_display_profile_reason(lora_display_profile_check(&p)), "controller_unconfirmed");
    p.controller_selected = 2;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_CONTROLLER_UNCONFIRMED);

    p = lead_profile();
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_OK);

    p = lead_profile(); p.vext_active_level = -1;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_UNSET);
    p = lead_profile(); p.rst = -1;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_UNSET);
    p = lead_profile(); p.i2c_addr = -1;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_UNSET);

    /* Every radio / FEM pin, including VFEM_Ctrl 7 and FEM PA 46, is refused. */
    const int radio[] = {2, 5, 7, 8, 9, 10, 11, 12, 13, 14, 46};
    for (size_t i = 0; i < sizeof radio / sizeof radio[0]; i++) {
        p = lead_profile(); p.vext = radio[i];
        CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_RADIO_PIN);
        p = lead_profile(); p.sda = radio[i];
        CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_RADIO_PIN);
    }

    const int bad[] = {19, 20, 22, 25, 26, 32, 49, 100, -2};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        p = lead_profile(); p.scl = bad[i];
        CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_BAD_GPIO);
    }

    p = lead_profile(); p.scl = p.sda;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_DUPLICATE_PIN);
    p = lead_profile(); p.vext = p.rst;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_DUPLICATE_PIN);

    p = lead_profile(); p.vext_active_level = 2;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_BAD_LEVEL);
    p = lead_profile(); p.i2c_addr = 0x78;  /* 8-bit form of 0x3C is a common mistake */
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_BAD_ADDR);
    p = lead_profile(); p.i2c_addr = 0x3D;
    CHECK(lora_display_profile_check(&p) == LORA_DISPLAY_PROFILE_OK);

    CHECK_STR(lora_display_profile_reason(LORA_DISPLAY_PROFILE_UNSET), "profile_unset");
    CHECK_STR(lora_display_profile_reason(LORA_DISPLAY_PROFILE_RADIO_PIN), "radio_pin_collision");
}

static lora_display_status_t listening(void)
{
    lora_display_status_t s;
    memset(&s, 0, sizeof s);
    s.radio = LORA_RADIO_OK;
    s.tx_limit = 20;
    s.rx_known = true;
    s.rx_count = 12;
    s.mac_known = true;
    const uint8_t mac[6] = {0xF8, 0x5B, 0x1B, 0xA2, 0x29, 0x14};
    memcpy(s.mac, mac, 6);
    s.uptime_s = 3723;
    return s;
}

static void test_layout(void)
{
    lora_display_text_t t;

    lora_display_layout(NULL, false, &t);
    CHECK_STR(t.line[0], "MUTINY LORA");
    CHECK_STR(t.line[7], "STATUS STARTING");
    CHECK_STR(t.line[3], "");

    lora_display_status_t s = listening();
    lora_display_layout(&s, false, &t);
    CHECK_STR(t.line[1], "NODE A22914");
    CHECK_STR(t.line[2], "RADIO OK ARM NO");
    CHECK_STR(t.line[3], "TX 0/20 AIR 0MS");
    CHECK_STR(t.line[4], "RX 12 ERR 0");
    CHECK_STR(t.line[5], "RSSI -- SNR --");   /* no packet yet: never shown as 0 */
    CHECK_STR(t.line[6], "UP 01:02:03");
    CHECK_STR(t.line[7], "STATUS DISARMED");

    s.last_rx_known = true; s.last_rssi_dbm = -87; s.last_snr_db = -3;
    lora_display_layout(&s, false, &t);
    CHECK_STR(t.line[5], "RSSI -87 SNR -3");

    s.armed = true; s.tx_count = 3; s.airtime_ms = 412;
    lora_display_layout(&s, false, &t);
    CHECK_STR(t.line[2], "RADIO OK ARM YES");
    CHECK_STR(t.line[3], "TX 3/20 AIR 412MS");
    CHECK_STR(t.line[7], "STATUS TX ARMED");

    /* Faults outrank armed. */
    s.fem_fault = true;
    CHECK_STR(lora_display_status_word(&s), "FEM FAULT");
    s.fem_fault = false; s.radio = LORA_RADIO_FAULT;
    lora_display_layout(&s, false, &t);
    CHECK_STR(t.line[2], "RADIO FAULT ARM YES");
    CHECK_STR(t.line[7], "STATUS RADIO FAULT");

    s = listening();
    s.radio = LORA_RADIO_UNKNOWN;
    s.rx_known = false; s.mac_known = false;
    lora_display_layout(&s, false, &t);
    CHECK_STR(t.line[1], "NODE --");
    CHECK_STR(t.line[2], "RADIO -- ARM NO");
    CHECK_STR(t.line[4], "RX -- ERR --");
    CHECK_STR(t.line[7], "STATUS STARTING");

    /* Stale overrides the status word but keeps the last values visible. */
    s = listening();
    lora_display_layout(&s, true, &t);
    CHECK_STR(t.line[4], "RX 12 ERR 0");
    CHECK_STR(t.line[7], "STATUS STALE");

    /* Long uptime switches to hours; huge counters are clipped to the row. */
    s.uptime_s = 100ull * 3600ull;
    s.tx_count = 4294967295u; s.tx_limit = 4294967295u; s.airtime_ms = 18446744073709551615ull;
    lora_display_layout(&s, false, &t);
    CHECK_STR(t.line[6], "UP 100H");
    CHECK(strlen(t.line[3]) == LORA_DISPLAY_COLS);
    for (int r = 0; r < LORA_DISPLAY_ROWS; r++) CHECK(strlen(t.line[r]) <= LORA_DISPLAY_COLS);
}

static void dump(const mono_fb_t *fb, int cols, int rows)
{
    for (int y = 0; y < rows * 8; y++) {
        for (int x = 0; x < cols * 6; x++) putchar(mono_fb_get(fb, x, y) ? '#' : '.');
        putchar('\n');
    }
}

static void test_fb(void)
{
    mono_fb_t fb;
    mono_fb_clear(&fb);
    for (int i = 0; i < MONO_FB_BYTES; i++) CHECK(fb.buf[i] == 0);

    mono_fb_char(&fb, 0, 0, '1');
    /* '1': centre column fully lit rows 0..6, row 7 blank, spacing column blank. */
    for (int y = 0; y < 7; y++) CHECK(mono_fb_get(&fb, 2, y) == 1);
    CHECK(mono_fb_get(&fb, 2, 7) == 0);
    for (int y = 0; y < 8; y++) CHECK(mono_fb_get(&fb, 5, y) == 0);

    /* Lowercase folds to uppercase; unknown characters render as '?'. */
    mono_fb_t a, b;
    mono_fb_clear(&a); mono_fb_clear(&b);
    mono_fb_char(&a, 0, 0, 'x'); mono_fb_char(&b, 0, 0, 'X');
    CHECK(memcmp(a.buf, b.buf, sizeof a.buf) == 0);
    mono_fb_clear(&a); mono_fb_clear(&b);
    mono_fb_char(&a, 0, 0, '~'); mono_fb_char(&b, 0, 0, '?');
    CHECK(memcmp(a.buf, b.buf, sizeof a.buf) == 0);

    /* Row 7 lands in the last page; column 21 starts at x=126 and is clipped. */
    mono_fb_clear(&fb);
    mono_fb_text(&fb, 0, 7, "MUTINY LORA STATUS OK!!");
    CHECK(mono_fb_get(&fb, 0, 56) == 1);   /* 'M' column 0 */
    mono_fb_char(&fb, 25, 0, 'M');         /* fully off-panel: no write */
    mono_fb_char(&fb, 0, 8, 'M');
    mono_fb_char(&fb, 0, -1, 'M');
    for (int x = 0; x < MONO_FB_W; x++) CHECK(fb.buf[x] == 0);

    mono_fb_clear(&fb);
    mono_fb_text(&fb, 0, 0, "MUTINY 0123456789");
    mono_fb_text(&fb, 0, 1, "RSSI -87 SNR -3 UP:");
    printf("--- glyph dump ---\n");
    dump(&fb, 19, 2);
}

int main(void)
{
    test_profile();
    test_layout();
    test_fb();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
