/* 128x64 monochrome framebuffer in SSD1306 page order: 8 pages of 128 column
 * bytes, bit 0 = top row of the page. Pure C, host-testable. */
#ifndef MONO_FB_H_INCLUDED
#define MONO_FB_H_INCLUDED

#include <stdint.h>

#define MONO_FB_W 128
#define MONO_FB_H 64
#define MONO_FB_BYTES (MONO_FB_W * MONO_FB_H / 8)

typedef struct {
    uint8_t buf[MONO_FB_BYTES];
} mono_fb_t;

void mono_fb_clear(mono_fb_t *fb);
int mono_fb_get(const mono_fb_t *fb, int x, int y);
/* Draws a 5x7 glyph in a 6x8 cell at text row/col. Characters outside the
 * built-in set render as '?'. Cells off the panel are clipped. */
void mono_fb_char(mono_fb_t *fb, int col, int row, char c);
void mono_fb_text(mono_fb_t *fb, int col, int row, const char *s);

#endif
