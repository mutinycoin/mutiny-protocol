/* Board profile for the LoRa bridge status OLED.
 *
 * Every value defaults to "unset" (-1). The display refuses to start until
 * each value is set for the exact board revision and a compatible controller
 * profile is selected. Pure C, host-testable. Configuration validity does not
 * establish fitted-chip identity or physical operation.
 *
 * Documented for HTIT-WB32LAF V4.3 (Heltec V4.3 schematic b846f7bb..., V4
 * pin map 2562d799...): SDA 17, SCL 18, OLED reset 21, Vext_Ctrl 36, and Vext
 * on = low (Vext_Ctrl drives the gate of P-channel Q2, pulled up by R14).
 * The fitted controller and its I2C address are NOT measured. */
#ifndef LORA_DISPLAY_PROFILE_H
#define LORA_DISPLAY_PROFILE_H

#include <stdint.h>

#define LORA_DISPLAY_PIN_UNSET (-1)

typedef struct {
    int sda;                  /* I2C data GPIO */
    int scl;                  /* I2C clock GPIO */
    int rst;                  /* OLED reset GPIO */
    int vext;                 /* panel power switch GPIO */
    int vext_active_level;    /* 0 or 1; -1 = unset */
    int i2c_addr;             /* 7-bit address, 0x3C or 0x3D; -1 = unset */
    int controller_selected; /* 1 selects documented compatible candidate; no physical proof */
} lora_display_profile_t;

typedef enum {
    LORA_DISPLAY_PROFILE_OK = 0,
    LORA_DISPLAY_PROFILE_UNSET,                  /* a required value is still -1 */
    LORA_DISPLAY_PROFILE_BAD_GPIO,               /* not a usable ESP32-S3 GPIO */
    LORA_DISPLAY_PROFILE_RADIO_PIN,              /* collides with the SX1262 / FEM pins */
    LORA_DISPLAY_PROFILE_DUPLICATE_PIN,          /* two display roles share a GPIO */
    LORA_DISPLAY_PROFILE_BAD_LEVEL,              /* vext_active_level not 0 or 1 */
    LORA_DISPLAY_PROFILE_BAD_ADDR,               /* not 0x3C or 0x3D */
    LORA_DISPLAY_PROFILE_CONTROLLER_UNCONFIRMED, /* panel controller not confirmed */
} lora_display_profile_result_t;

lora_display_profile_result_t lora_display_profile_check(const lora_display_profile_t *p);
const char *lora_display_profile_reason(lora_display_profile_result_t r);

#endif
