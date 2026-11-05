#include "lora_display_profile.h"

#include <stddef.h>

/* Radio-side pins on HTIT-WB32LAF V4.3: FEM CSD 2, FEM CTX 5, VFEM_Ctrl 7
 * (FEM supply, hardware pull-up, left untouched by the bridge), FEM PA 46, and
 * the SX1262 bus NSS 8, SCK 9, MOSI 10, MISO 11, RESET 12, BUSY 13, DIO1 14. */
static const int radio_pins[] = {2, 5, 7, 8, 9, 10, 11, 12, 13, 14, 46};

/* ESP32-S3: GPIO 0..21 and 26..48 exist. 19/20 are native USB, 26..32 are the
 * SPI flash / PSRAM bus on module boards; none of those may drive the panel. */
static int usable_gpio(int g)
{
    if (g < 0 || g > 48) return 0;
    if (g >= 22 && g <= 25) return 0;
    if (g == 19 || g == 20) return 0;
    if (g >= 26 && g <= 32) return 0;
    return 1;
}

static int radio_pin(int g)
{
    for (size_t i = 0; i < sizeof radio_pins / sizeof radio_pins[0]; i++)
        if (radio_pins[i] == g) return 1;
    return 0;
}

lora_display_profile_result_t lora_display_profile_check(const lora_display_profile_t *p)
{
    if (!p) return LORA_DISPLAY_PROFILE_UNSET;
    const int pins[4] = {p->sda, p->scl, p->rst, p->vext};

    for (int i = 0; i < 4; i++)
        if (pins[i] == LORA_DISPLAY_PIN_UNSET) return LORA_DISPLAY_PROFILE_UNSET;
    if (p->vext_active_level == LORA_DISPLAY_PIN_UNSET) return LORA_DISPLAY_PROFILE_UNSET;
    if (p->i2c_addr == LORA_DISPLAY_PIN_UNSET) return LORA_DISPLAY_PROFILE_UNSET;

    for (int i = 0; i < 4; i++)
        if (!usable_gpio(pins[i])) return LORA_DISPLAY_PROFILE_BAD_GPIO;
    for (int i = 0; i < 4; i++)
        if (radio_pin(pins[i])) return LORA_DISPLAY_PROFILE_RADIO_PIN;
    for (int i = 0; i < 4; i++)
        for (int j = i + 1; j < 4; j++)
            if (pins[i] == pins[j]) return LORA_DISPLAY_PROFILE_DUPLICATE_PIN;

    if (p->vext_active_level != 0 && p->vext_active_level != 1) return LORA_DISPLAY_PROFILE_BAD_LEVEL;
    if (p->i2c_addr != 0x3C && p->i2c_addr != 0x3D) return LORA_DISPLAY_PROFILE_BAD_ADDR;
    if (p->controller_selected != 1) return LORA_DISPLAY_PROFILE_CONTROLLER_UNCONFIRMED;
    return LORA_DISPLAY_PROFILE_OK;
}

const char *lora_display_profile_reason(lora_display_profile_result_t r)
{
    switch (r) {
    case LORA_DISPLAY_PROFILE_OK:             return "ok";
    case LORA_DISPLAY_PROFILE_UNSET:          return "profile_unset";
    case LORA_DISPLAY_PROFILE_BAD_GPIO:       return "bad_gpio";
    case LORA_DISPLAY_PROFILE_RADIO_PIN:      return "radio_pin_collision";
    case LORA_DISPLAY_PROFILE_DUPLICATE_PIN:  return "duplicate_pin";
    case LORA_DISPLAY_PROFILE_BAD_LEVEL:      return "bad_vext_level";
    case LORA_DISPLAY_PROFILE_BAD_ADDR:       return "bad_i2c_addr";
    case LORA_DISPLAY_PROFILE_CONTROLLER_UNCONFIRMED: return "controller_unconfirmed";
    }
    return "unknown";
}
