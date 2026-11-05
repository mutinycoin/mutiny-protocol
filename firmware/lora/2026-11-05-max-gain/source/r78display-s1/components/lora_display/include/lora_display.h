/* LoRa bridge status OLED (ESP-IDF side).
 *
 * Off unless CONFIG_LORA_DISPLAY_ENABLE=y AND the Kconfig board profile passes
 * lora_display_profile_check(). The display owns its own I2C bus and a
 * low-priority task; it never touches the radio SPI bus, publishing is non-blocking. Runtime radio interference still needs measurement. */
#ifndef LORA_DISPLAY_H
#define LORA_DISPLAY_H

#include "esp_err.h"
#include "lora_display_model.h"

/* Call once, after the radio is initialised. Returns:
 *   ESP_ERR_NOT_SUPPORTED  display disabled in Kconfig
 *   ESP_ERR_INVALID_ARG    board profile unset or invalid (reason logged)
 *   ESP_OK                 task created; panel bring-up is asynchronous
 *   other                  queue/task creation failed
 * Inspect lora_display_state() for later panel failure. State and accepting
 * are independently atomic, not a consistent two-field snapshot. */
esp_err_t lora_display_start(void);

/* Non-blocking: overwrites the pending snapshot. Safe to call from the radio
 * loop at any rate; a no-op when the display is not running. */
void lora_display_publish(const lora_display_status_t *s);

/* Short machine-readable state for the bridge status record:
 * "disabled", "profile_unset", ..., "running", "failed". */
const char *lora_display_state(void);

#endif
