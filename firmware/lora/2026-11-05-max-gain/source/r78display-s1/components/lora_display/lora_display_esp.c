/* ESP-IDF 5.5 glue for documented V4 SSD1315/SSD1306-compatible candidate.
 * Physical panel and current installed image remain unverified.
 * Profile selection is not a hardware identity assertion.
 * ESP-IDF glue for the LoRa bridge status OLED (128x64, I2C).
 * Source only: not compiled or flashed on ASUS. Pin values come solely from
 * Kconfig and must pass lora_display_profile_check() before any GPIO is set.
 *
 * Isolation from the radio: lora_display_start() only validates the profile
 * and creates the task. Panel power, reset, the I2C bus (and so its interrupt)
 * and every panel write happen inside the display task, which is pinned to the
 * core the caller is NOT running on, at low priority. The radio loop only ever
 * calls lora_display_publish(), a non-blocking length-1 queue overwrite. */
#include "lora_display.h"
#include "lora_display_profile.h"
#include "lora_display_lifecycle.h"
#include "mono_fb.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "lora_display";

#define I2C_TIMEOUT_MS 50
#define STALE_MS 5000

static lora_display_lifecycle_t lifecycle = LORA_DISPLAY_LIFECYCLE_INITIALIZER;
/* Initialized before accepting-release and never deleted/replaced in this boot.
 * A publisher already admitted during stop may overwrite this still-valid queue;
 * it cannot use a freed handle. No post-stop delivery guarantee is claimed. */
static QueueHandle_t snapshot_q;
static i2c_master_bus_handle_t bus;
static i2c_master_dev_handle_t dev;
static lora_display_profile_t profile;

const char *lora_display_state(void) { return lora_display_get_state(&lifecycle); }

void lora_display_publish(const lora_display_status_t *s)
{
    if (s && lora_display_accepting(&lifecycle)) xQueueOverwrite(snapshot_q, s);
}

#if CONFIG_LORA_DISPLAY_ENABLE

static esp_err_t cmd(const uint8_t *c, size_t n)
{
    uint8_t buf[8];
    if (n + 1 > sizeof buf) return ESP_ERR_INVALID_SIZE;
    buf[0] = 0x00; /* control byte: command stream */
    memcpy(buf + 1, c, n);
    return i2c_master_transmit(dev, buf, n + 1, I2C_TIMEOUT_MS);
}

static esp_err_t push(const mono_fb_t *fb)
{
    static const uint8_t window[] = {0x21, 0x00, 0x7F, 0x22, 0x00, 0x07};
    esp_err_t err = cmd(window, sizeof window);
    static uint8_t chunk[1 + MONO_FB_W];
    chunk[0] = 0x40; /* control byte: data stream */
    for (int page = 0; err == ESP_OK && page < MONO_FB_H / 8; page++) {
        memcpy(chunk + 1, fb->buf + page * MONO_FB_W, MONO_FB_W);
        err = i2c_master_transmit(dev, chunk, sizeof chunk, I2C_TIMEOUT_MS);
    }
    return err;
}

static void panel_power(bool on)
{
    int level = on ? profile.vext_active_level : !profile.vext_active_level;
    gpio_set_level((gpio_num_t)profile.vext, (uint32_t)level);
}

static esp_err_t panel_init(void)
{
    static const uint8_t seq[][3] = {
        {0xAE},             /* display off */
        {0xD5, 0xF0},       /* clock divide */
        {0xA8, 0x3F},       /* multiplex 64 */
        {0xD3, 0x00},       /* display offset 0 */
        {0x40},             /* start line 0 */
        {0x8D, 0x14},       /* charge pump on */
        {0x20, 0x00},       /* horizontal addressing */
        {0xA1},             /* segment remap */
        {0xC8},             /* COM scan descending */
        {0xDA, 0x12},       /* COM pins */
        {0x81, 0xCF},       /* contrast */
        {0xD9, 0xF1},       /* precharge */
        {0xDB, 0x40},       /* VCOMH */
        {0xA4},             /* resume from RAM */
        {0xA6},             /* normal (not inverted) */
        {0x2E},             /* stop scroll, as in V4 vendor driver */
    };
    static const uint8_t len[] = {1, 2, 2, 2, 1, 2, 2, 1, 1, 2, 2, 2, 2, 1, 1, 1};
    for (size_t i = 0; i < sizeof len; i++) {
        esp_err_t err = cmd(seq[i], len[i]);
        if (err != ESP_OK) return err;
    }
    static mono_fb_t blank;
    mono_fb_clear(&blank);
    esp_err_t err = push(&blank);
    if (err != ESP_OK) return err;
    static const uint8_t on[] = {0xAF};
    return cmd(on, 1);
}

static esp_err_t panel_bring_up(void)
{
    /* Vext held off while its pin becomes an output; reset held high. */
    panel_power(false);
    gpio_set_level((gpio_num_t)profile.rst, 1);
    const gpio_config_t out = {
        .pin_bit_mask = (UINT64_C(1) << profile.vext) | (UINT64_C(1) << profile.rst),
        .mode = GPIO_MODE_OUTPUT,
    };
    esp_err_t err = gpio_config(&out);
    if (err != ESP_OK) return err;
    panel_power(true);
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_set_level((gpio_num_t)profile.rst, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level((gpio_num_t)profile.rst, 1);
    vTaskDelay(pdMS_TO_TICKS(20));

    const i2c_master_bus_config_t bus_cfg = {
        .i2c_port = -1,
        .sda_io_num = profile.sda,
        .scl_io_num = profile.scl,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    err = i2c_new_master_bus(&bus_cfg, &bus);
    if (err != ESP_OK) return err;
    const i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = (uint16_t)profile.i2c_addr,
        .scl_speed_hz = 400000,
    };
    err = i2c_master_bus_add_device(bus, &dev_cfg, &dev);
    if (err != ESP_OK) return err;
    return panel_init();
}

/* Non-fatal for the bridge: release the bus, power the panel off, stop. */
static void stop(const char *why, esp_err_t err)
{
    ESP_LOGW(TAG, "%s: %s; display stopped", why, esp_err_to_name(err));
    lora_display_accept(&lifecycle, false);
    lora_display_set_state(&lifecycle, "failed");
    if (dev) { i2c_master_bus_rm_device(dev); dev = NULL; }
    if (bus) { i2c_del_master_bus(bus); bus = NULL; }
    panel_power(false);
    vTaskDelete(NULL);
}

static void display_task(void *arg)
{
    (void)arg;
    esp_err_t err = panel_bring_up();
    if (err != ESP_OK) stop("panel bring-up failed", err);
    lora_display_set_state(&lifecycle, "running");

    static lora_display_status_t snap;
    static mono_fb_t fb;
    static lora_display_text_t text;
    bool have = false;
    TickType_t last = xTaskGetTickCount();

    for (;;) {
        if (xQueueReceive(snapshot_q, &snap, pdMS_TO_TICKS(1000)) == pdTRUE) {
            have = true;
            last = xTaskGetTickCount();
        }
        bool stale = have && (xTaskGetTickCount() - last) > pdMS_TO_TICKS(STALE_MS);
        lora_display_layout(have ? &snap : NULL, stale, &text);
        mono_fb_clear(&fb);
        for (int r = 0; r < LORA_DISPLAY_ROWS; r++) mono_fb_text(&fb, 0, r, text.line[r]);
        err = push(&fb);
        if (err != ESP_OK) stop("panel write failed", err);
    }
}

esp_err_t lora_display_start(void)
{
    if (snapshot_q) return ESP_ERR_INVALID_STATE; /* once per boot */
    profile = (lora_display_profile_t){
        .sda = CONFIG_LORA_DISPLAY_SDA_GPIO,
        .scl = CONFIG_LORA_DISPLAY_SCL_GPIO,
        .rst = CONFIG_LORA_DISPLAY_RST_GPIO,
        .vext = CONFIG_LORA_DISPLAY_VEXT_GPIO,
        .vext_active_level = CONFIG_LORA_DISPLAY_VEXT_ACTIVE_LEVEL,
        .i2c_addr = CONFIG_LORA_DISPLAY_I2C_ADDR,
#if CONFIG_LORA_DISPLAY_SSD13XX_VENDOR_PROFILE_CANDIDATE
        .controller_selected = 1,
#else
        .controller_selected = 0,
#endif
    };
    lora_display_profile_result_t pr = lora_display_profile_check(&profile);
    if (pr != LORA_DISPLAY_PROFILE_OK) {
        lora_display_set_state(&lifecycle, lora_display_profile_reason(pr));
        ESP_LOGW(TAG, "not started: %s", lora_display_profile_reason(pr));
        return ESP_ERR_INVALID_ARG;
    }

    snapshot_q = xQueueCreate(1, sizeof(lora_display_status_t));
    if (!snapshot_q) {
        lora_display_set_state(&lifecycle, "failed");
        return ESP_ERR_NO_MEM;
    }
#if CONFIG_FREERTOS_UNICORE
    const BaseType_t core = tskNO_AFFINITY;
#else
    const BaseType_t core = xPortGetCoreID() == 0 ? 1 : 0;
#endif
    lora_display_set_state(&lifecycle, "starting");
    lora_display_accept(&lifecycle, true);
    if (xTaskCreatePinnedToCore(display_task, "lora_display", 4096, NULL, CONFIG_LORA_DISPLAY_TASK_PRIORITY, NULL, core) != pdPASS) {
        lora_display_accept(&lifecycle, false);
        lora_display_set_state(&lifecycle, "failed");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

#else /* !CONFIG_LORA_DISPLAY_ENABLE */

esp_err_t lora_display_start(void)
{
    (void)profile; (void)bus; (void)dev; (void)TAG;
    lora_display_set_state(&lifecycle, "disabled");
    return ESP_ERR_NOT_SUPPORTED;
}

#endif
