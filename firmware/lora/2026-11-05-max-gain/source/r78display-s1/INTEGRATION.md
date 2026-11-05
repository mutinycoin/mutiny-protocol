# LoRa bridge status display: integration notes (source only)

## Layout
- **`components/lora_display`:** the display component. It is off by default (`CONFIG_LORA_DISPLAY_ENABLE=n`).
- **`bridge-overlay/`:** the byte-exact historical original bridge2 source from R52 `hardware/retained-bridge-source`, with display hooks added. The R52 originals are not modified (bridge_main.c is still 2dc40abe…). `partitions-preflight.csv` and `sdkconfig.defaults` are copied unchanged.
- **`BRIDGE-OVERLAY-DIFF.txt`:** the full overlay delta (fc.exe output).
- **`bridge-overlay/profiles/heltec-wifi-lora-32-v4.3-documented.defaults`:** the documented V4.3 pins. The I2C address and controller confirmation are left unset, so the display still refuses to start.
- **`test/run-host-tests.ps1`:** host tests run with the pinned MSVC at /W4 /WX.

## Overlay delta (all in bridge_main.c, every hook inside `#if CONFIG_LORA_DISPLAY_ENABLE` except the include)
1. `#include "lora_display.h"`.
2. `display_publish()` copies bridge state into a `lora_display_status_t`. The fields are `radio_ok`, `armed`, `tx_count`, `TX_LIMIT_PER_BOOT`, `airtime_us/1000`, `rx_count`, `rx_errors`, the last received RSSI and SNR, the uptime and the MAC. It then calls `lora_display_publish()`, which is an `xQueueOverwrite` and never blocks.
3. `bridge_deliver()` records RSSI and SNR after a good packet, using the same formulas as the "R" line.
4. `app_main()`: `lora_display_start()` runs once, after the radio start and the boot record. Its result is ignored.
5. Main loop: after the DIO1 delivery check, the loop publishes at most once a second.

Radio commands, timing, FEM handling, arming, budgets and console records are unchanged. GPIO7 (VFEM_Ctrl) is still left untouched. The `LORA-BRIDGE-STATUS-V0` record is unchanged on purpose, because the host adapter's parser is strict about it.

Build files:
- The top-level CMakeLists.txt adds `EXTRA_COMPONENT_DIRS` for the component and renames the project to `mutiny_lora_bridge_display`, so it cannot be confused with bridge2.
- `main/CMakeLists.txt` adds `lora_display` to `PRIV_REQUIRES`.

## Isolation
- `lora_display_start()` only validates the profile and creates the task.
- Vext, reset, the I2C bus (and its interrupt) and all panel writes happen in the display task. That task is pinned to the core the caller is not running on, at priority 1.
- Each I2C write has a 50 ms timeout. On any failure the task releases the bus, powers the panel off and exits; the bridge is unaffected.
- The profile check refuses:
  - the radio and FEM pins 2, 5, 7, 8 to 14 and 46;
  - USB pins 19 and 20, and flash/PSRAM pins 26 to 32;
  - duplicate pins;
  - an unset or invalid Vext level or I2C address;
  - an unconfirmed controller.
- When the display is enabled and refused, it emits one ESP_LOGW line on the console, in the same form as the IDF boot log lines.

## V4.3 facts
- **Documented:** SDA 17, SCL 18, OLED_RST 21, Vext_Ctrl 36.
- **Vext:** on = LOW. Vext_Ctrl drives the gate of P-channel Q2 (AO3401A) through R10, with R14 pulling it up to 3V3; Q2 enables the Vext LDO U2.
- **Not measured:** the fitted controller (SSD1306 is a family lead) and its I2C address. Both stay unset until confirmed.

## Not done
- No ESP32-S3 compile of `lora_display_esp.c` or the overlay. That is for Forge to do on the laptop IDF 5.5.5.
- No device, port, flash or RF action.
