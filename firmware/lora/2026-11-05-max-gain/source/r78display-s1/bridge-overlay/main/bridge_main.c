/* Mutiny Build 8 LoRa bench packet bridge. TEST ONLY; not a relay, not
 * qualified for anything. Heltec HTIT-WB32LAF V4.3 (ESP32-S3, SX1262).
 *
 * WHAT IT IS: a transparent radio modem for bench tests. A packet of 1 to 255
 * bytes handed to it over USB is transmitted unchanged; every packet it
 * receives is handed to the host unchanged with its signal strength. It adds
 * no header, performs no cryptography, keeps no session and makes no decision
 * about the bytes. It confers no trust: whatever authenticates the traffic
 * lives entirely in the hosts.
 *
 * LIMITS, compile-time: never transmits at boot or by itself; transmits only
 * while armed with the exact phrase in the same boot; one fixed channel
 * inside the 500 kHz configuration of FCC ID 2A2GJ-HTIT-WBR2H at the radio
 * chip's lowest power setting (power at the antenna not measured); at most
 * TX_LIMIT_PER_BOOT packets and AIRTIME_LIMIT_US of measured transmit time
 * per boot, after which it disarms. No Wi-Fi, Bluetooth or flash writes.
 * Half duplex: the hosts must take turns. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_idf_version.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lora_display.h"

#if !defined(CONFIG_IDF_TARGET_ESP32S3)
#error "This test targets ESP32-S3 only"
#endif
#if !defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
#error "Native USB Serial/JTAG console is required"
#endif
#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED)
#error "Development test forbids Secure Boot and flash encryption"
#endif

/* ---- Board wiring (V4.3 schematic, as recorded in the LoRa handoff) ---- */
#define PIN_NSS   GPIO_NUM_8
#define PIN_SCK   GPIO_NUM_9
#define PIN_MOSI  GPIO_NUM_10
#define PIN_MISO  GPIO_NUM_11
#define PIN_RESET GPIO_NUM_12
#define PIN_BUSY  GPIO_NUM_13
#define PIN_DIO1  GPIO_NUM_14
#define PIN_FEM_CSD GPIO_NUM_2 /* front end chip enable: 0 = shutdown */
#define PIN_FEM_CTX GPIO_NUM_5 /* 1 = transmit path, 0 = receive low-noise amplifier */
/* The front-end supply enable (GPIO7) has a hardware pull-up and is left
 * untouched. Its transmit/receive select CPS is the radio's DIO2. */

/* ---- Fixed radio settings: change only by reviewed source edit ---- */
#define RF_FREQUENCY_HZ   925100000u /* channel 04 of the certified 500 kHz list */
#define LORA_SF           7u
#define LORA_BW_500K      0x06u
#define LORA_CR_4_5       0x01u
#define LORA_PREAMBLE     8u
#define TX_POWER_SETTING  (22)       
#define PA_DUTY_CYCLE     0x04u      /* high-power amplifier configuration for +22 dBm */
#define PA_HP_MAX         0x02u
#define TX_LIMIT_PER_BOOT 6000u
#define AIRTIME_LIMIT_US  UINT64_C(300000000) /* five minutes of transmit time per boot */
#define ARM_PHRASE        "L-ARM I-ACCEPT-BENCH-TRANSMISSION"
_Static_assert(RF_FREQUENCY_HZ >= 923300000u && RF_FREQUENCY_HZ <= 927500000u, "outside the certified 500 kHz channel range");

static spi_device_handle_t radio;
static bool radio_ok, armed;
static unsigned tx_count;
static uint8_t mac[6];

static void fem_shutdown(void) { gpio_set_level(PIN_FEM_CTX, 0); gpio_set_level(PIN_FEM_CSD, 0); }
static void fem_receive(void)  { gpio_set_level(PIN_FEM_CTX, 0); gpio_set_level(PIN_FEM_CSD, 1); }
static void fem_transmit(void) { gpio_set_level(PIN_FEM_CTX, 1); gpio_set_level(PIN_FEM_CSD, 1); }

static bool wait_ready(unsigned timeout_ms)
{
    int64_t end = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (gpio_get_level(PIN_BUSY)) {
        if (esp_timer_get_time() > end) {
            return false;
        }
        vTaskDelay(1);
    }
    return true;
}

/* One SPI command: opcode and parameters out, the same number of bytes in. */
static bool command(const uint8_t *out, uint8_t *in, size_t n)
{
    static uint8_t scratch[3 + 255];
    if (n == 0 || n > sizeof scratch || !wait_ready(100)) {
        return false;
    }
    spi_transaction_t t = {.length = n * 8, .tx_buffer = out, .rx_buffer = in ? in : scratch};
    return spi_device_polling_transmit(radio, &t) == ESP_OK;
}
#define CMD(...) command((const uint8_t[]){__VA_ARGS__}, NULL, sizeof((const uint8_t[]){__VA_ARGS__}))

static bool write_register(uint16_t address, uint8_t value)
{
    return CMD(0x0D, (uint8_t)(address >> 8), (uint8_t)address, value);
}
static bool read_register(uint16_t address, uint8_t *value)
{
    const uint8_t out[5] = {0x1D, (uint8_t)(address >> 8), (uint8_t)address, 0, 0};
    uint8_t in[5];
    if (!command(out, in, 5)) {
        return false;
    }
    *value = in[4];
    return true;
}
static uint16_t irq_status(void)
{
    const uint8_t out[4] = {0x12, 0, 0, 0};
    uint8_t in[4] = {0};
    return command(out, in, 4) ? (uint16_t)((in[2] << 8) | in[3]) : 0xFFFF;
}
static void irq_clear(void) { (void)CMD(0x02, 0xFF, 0xFF); }
static void standby(void)   { (void)CMD(0x80, 0x00); }

static bool radio_start(void)
{
    const gpio_config_t outputs = {.pin_bit_mask = (UINT64_C(1) << PIN_FEM_CSD) | (UINT64_C(1) << PIN_FEM_CTX) | (UINT64_C(1) << PIN_RESET),
                                   .mode = GPIO_MODE_OUTPUT, .pull_down_en = GPIO_PULLDOWN_DISABLE};
    const gpio_config_t inputs = {.pin_bit_mask = (UINT64_C(1) << PIN_BUSY) | (UINT64_C(1) << PIN_DIO1), .mode = GPIO_MODE_INPUT};
    /* Front end held in shutdown before its pins become outputs. */
    gpio_set_level(PIN_FEM_CSD, 0);
    gpio_set_level(PIN_FEM_CTX, 0);
    gpio_set_level(PIN_RESET, 1);
    if (gpio_config(&outputs) != ESP_OK || gpio_config(&inputs) != ESP_OK) {
        return false;
    }
    fem_shutdown();
    /* Whole 255-byte packets go out in one transaction, which needs the DMA path (64 bytes is the limit without it). */
    const spi_bus_config_t bus = {.mosi_io_num = PIN_MOSI, .miso_io_num = PIN_MISO, .sclk_io_num = PIN_SCK, .quadwp_io_num = -1, .quadhd_io_num = -1,
                                  .max_transfer_sz = 3 + 255};
    const spi_device_interface_config_t device = {.clock_speed_hz = 2000000, .mode = 0, .spics_io_num = PIN_NSS, .queue_size = 1};
    if (spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK || spi_bus_add_device(SPI2_HOST, &device, &radio) != ESP_OK) {
        return false;
    }
    gpio_set_level(PIN_RESET, 0);
    vTaskDelay(pdMS_TO_TICKS(2));
    gpio_set_level(PIN_RESET, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    if (!wait_ready(200)) {
        return false;
    }
    const uint32_t frf = (uint32_t)(((uint64_t)RF_FREQUENCY_HZ << 25) / 32000000u);
    uint8_t sync_high = 0, sync_low = 0, clamp = 0, iq = 0;
    bool ok = CMD(0x80, 0x00)                         /* standby on the internal oscillator */
        && CMD(0x97, 0x02, 0x00, 0x01, 0x40)          /* DIO3 powers the TCXO at 1.8 V, 5 ms start */
        && CMD(0x07, 0x00, 0x00)                      /* clear the start-up oscillator error flag */
        && CMD(0x89, 0x7F)                            /* calibrate all blocks */
        && wait_ready(200)
        && CMD(0x9D, 0x01)                            /* DIO2 drives the front end's transmit select */
        && CMD(0x96, 0x00)                            /* linear regulator only */
        && CMD(0x8A, 0x01)                            /* LoRa packets */
        && CMD(0x86, (uint8_t)(frf >> 24), (uint8_t)(frf >> 16), (uint8_t)(frf >> 8), (uint8_t)frf)
        && CMD(0x98, 0xE1, 0xE9)                      /* image calibration for 902 to 928 MHz */
        && wait_ready(200)
        && CMD(0x95, PA_DUTY_CYCLE, PA_HP_MAX, 0x00, 0x01)
        && CMD(0x8E, (uint8_t)(int8_t)TX_POWER_SETTING, 0x04) /* 200 us ramp */
        && CMD(0x8F, 0x00, 0x00)
        && CMD(0x8B, LORA_SF, LORA_BW_500K, LORA_CR_4_5, 0x00)
        && CMD(0x8C, 0x00, LORA_PREAMBLE, 0x00, 0xFF, 0x01, 0x00)          /* explicit header, CRC on, standard IQ */
        && CMD(0x08, 0x02, 0x63, 0x02, 0x63, 0x00, 0x00, 0x00, 0x00)       /* TX done, RX done, header and CRC error, timeout on DIO1 */
        && read_register(0x0740, &sync_high) && read_register(0x0741, &sync_low);
    /* Datasheet workarounds: transmit clamp, standard IQ polarity. */
    ok = ok && read_register(0x08D8, &clamp) && write_register(0x08D8, clamp | 0x1E)
            && read_register(0x0736, &iq) && write_register(0x0736, iq | 0x04);
    printf("{\"schema\":\"LORA-LINKTEST-RADIO-V0\",\"radio_started\":%s,\"sync_word\":\"%02x%02x\",\"frequency_hz\":%u,"
           "\"sf\":%u,\"bandwidth_khz\":500,\"coding_rate\":\"4/5\",\"tx_power_setting\":%d,\"pa_duty\":%u,\"pa_hpmax\":%u}\n",
           ok ? "true" : "false", sync_high, sync_low, (unsigned)RF_FREQUENCY_HZ, (unsigned)LORA_SF, TX_POWER_SETTING,
           (unsigned)PA_DUTY_CYCLE, (unsigned)PA_HP_MAX);
    /* The public LoRa sync word 0x1424 is the chip default; anything else means the chip did not answer as an SX126x. */
    return ok && sync_high == 0x14 && sync_low == 0x24;
}

/* ---- Bridge ---------------------------------------------------------- */

static uint64_t airtime_us;      /* measured transmit time this boot */
static unsigned rx_count, rx_errors;

#if CONFIG_LORA_DISPLAY_ENABLE
/* Display overlay: read-only copies of bridge state, handed to the status
 * OLED task through a non-blocking queue overwrite. Never touches the radio. */
static bool display_rx_seen;
static int16_t display_rssi_dbm;
static int8_t display_snr_db;

static void display_publish(void)
{
    lora_display_status_t s = {
        .radio = radio_ok ? LORA_RADIO_OK : LORA_RADIO_FAULT,
        .armed = armed,
        .tx_count = tx_count,
        .tx_limit = TX_LIMIT_PER_BOOT,
        .airtime_ms = airtime_us / 1000,
        .rx_known = true,
        .rx_count = rx_count,
        .rx_errors = rx_errors,
        .last_rx_known = display_rx_seen,
        .last_rssi_dbm = display_rssi_dbm,
        .last_snr_db = display_snr_db,
        .uptime_s = (uint64_t)esp_timer_get_time() / 1000000u,
        .mac_known = true,
    };
    memcpy(s.mac, mac, sizeof s.mac);
    lora_display_publish(&s);
}
#endif

static int hex_value(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Transmit one host-supplied packet of 1 to 255 bytes, then return to receive. */
static const char *bridge_send(const uint8_t *payload, size_t length)
{
    if (!radio_ok || !armed) {
        return "NOT_ARMED";
    }
    if (length == 0 || length > 255) {
        return "BAD_LENGTH";
    }
    if (tx_count >= TX_LIMIT_PER_BOOT || airtime_us >= AIRTIME_LIMIT_US) {
        armed = false;
        return "BUDGET_SPENT";
    }
    static uint8_t frame[2 + 255];
    uint8_t workaround = 0;
    frame[0] = 0x0E;
    frame[1] = 0x00;
    memcpy(frame + 2, payload, length);
    standby();
    irq_clear();
    bool ok = CMD(0x8C, 0x00, LORA_PREAMBLE, 0x00, (uint8_t)length, 0x01, 0x00)
        && read_register(0x0889, &workaround) && write_register(0x0889, workaround & 0xFB)
        && command(frame, NULL, 2 + length);
    if (ok) {
        fem_transmit();
        ok = CMD(0x83, 0x00, 0x32, 0x00);           /* transmit, 200 ms timeout */
    }
    uint16_t irq = 0;
    int64_t start = esp_timer_get_time();
    while (ok && esp_timer_get_time() - start < 600000) {
        if (gpio_get_level(PIN_DIO1)) {
            irq = irq_status();
            break;
        }
    }
    int64_t elapsed = esp_timer_get_time() - start;
    tx_count++;
    airtime_us += (uint64_t)elapsed;
    /* Back to listening at once: the other side may answer immediately. */
    standby();
    irq_clear();
    fem_receive();
    bool listening = CMD(0x8C, 0x00, LORA_PREAMBLE, 0x00, 0xFF, 0x01, 0x00) && CMD(0x82, 0xFF, 0xFF, 0xFF);
    if (!listening) {
        standby();
        fem_shutdown();
        armed = false;
        return "RECEIVE_RESTART_FAILED";
    }
    return ok && (irq & 0x0001) ? NULL : "TRANSMIT_FAILED";
}

/* Deliver one received packet to the host as a text line. */
static void bridge_deliver(void)
{
    uint16_t irq = irq_status();
    irq_clear();
    if (!(irq & 0x0002) || (irq & 0x0060)) {
        rx_errors++;
        return;
    }
    const uint8_t status_out[4] = {0x13, 0, 0, 0}, packet_out[5] = {0x14, 0, 0, 0, 0};
    uint8_t status_in[4] = {0}, packet_in[5] = {0};
    static uint8_t out[3 + 255], in[3 + 255];
    if (!command(status_out, status_in, 4) || !command(packet_out, packet_in, 5)) {
        rx_errors++;
        return;
    }
    unsigned length = status_in[2];
    memset(out, 0, sizeof out);
    out[0] = 0x1E;
    out[1] = status_in[3];
    if (length == 0 || !command(out, in, 3 + length)) {
        rx_errors++;
        return;
    }
    static char line[16 + 2 * 255 + 2];
    int used = snprintf(line, sizeof line, "R %d %d ", -(int)packet_in[2] / 2, (int)(int8_t)packet_in[3] / 4);
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < length; i++) {
        line[used++] = digits[in[3 + i] >> 4];
        line[used++] = digits[in[3 + i] & 15];
    }
    line[used++] = '\n';
    line[used] = 0;
    fputs(line, stdout);
    fflush(stdout);
    rx_count++;
#if CONFIG_LORA_DISPLAY_ENABLE
    display_rx_seen = true;
    display_rssi_dbm = (int16_t)(-(int)packet_in[2] / 2);
    display_snr_db = (int8_t)((int)(int8_t)packet_in[3] / 4);
#endif
}

static void status(void)
{
    printf("{\"schema\":\"LORA-BRIDGE-STATUS-V0\",\"radio\":%s,\"armed\":%s,\"tx_count\":%u,\"tx_limit\":%u,\"airtime_ms\":%llu,"
           "\"airtime_limit_ms\":%llu,\"rx_count\":%u,\"rx_errors\":%u,\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"free_heap\":%lu}\n",
           radio_ok ? "true" : "false", armed ? "true" : "false", tx_count, (unsigned)TX_LIMIT_PER_BOOT,
           (unsigned long long)(airtime_us / 1000), (unsigned long long)(AIRTIME_LIMIT_US / 1000), rx_count, rx_errors,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (unsigned long)esp_get_free_heap_size());
}

/* Console lines:
 *   L-STATUS                      status record
 *   L-ARM I-ACCEPT-BENCH-TRANSMISSION   arm and start listening
 *   L-DISARM                      stop listening, front end off
 *   S <hex of 1..255 bytes>       transmit that packet (armed only); answers "T OK" or "T <reason>"
 * Received packets are printed as "R <rssi_dbm> <snr_db> <hex>". */
static void handle(char *line)
{
    if (!strcmp(line, "L-STATUS")) {
        status();
    } else if (!strcmp(line, ARM_PHRASE)) {
        armed = false;
        if (radio_ok) {
            standby();
            irq_clear();
            fem_receive();
            armed = CMD(0x8C, 0x00, LORA_PREAMBLE, 0x00, 0xFF, 0x01, 0x00) && CMD(0x82, 0xFF, 0xFF, 0xFF);
            if (!armed) {
                standby();
                fem_shutdown();
            }
        }
        printf("{\"schema\":\"LORA-BRIDGE-ARM-V0\",\"armed\":%s}\n", armed ? "true" : "false");
    } else if (!strcmp(line, "L-DISARM")) {
        armed = false;
        standby();
        fem_shutdown();
        printf("{\"schema\":\"LORA-BRIDGE-ARM-V0\",\"armed\":false}\n");
    } else if (line[0] == 'S' && line[1] == ' ') {
        static uint8_t payload[255];
        size_t n = strlen(line + 2), length = n / 2;
        const char *problem = (n == 0 || n % 2 || length > 255) ? "BAD_HEX" : NULL;
        for (size_t i = 0; !problem && i < length; i++) {
            int a = hex_value(line[2 + 2 * i]), b = hex_value(line[3 + 2 * i]);
            if (a < 0 || b < 0) {
                problem = "BAD_HEX";
            } else {
                payload[i] = (uint8_t)(a * 16 + b);
            }
        }
        if (!problem) {
            problem = bridge_send(payload, length);
        }
        printf("T %s\n", problem ? problem : "OK");
    } else {
        printf("{\"schema\":\"LORA-BRIDGE-COMMAND-V0\",\"result\":\"UNKNOWN\"}\n");
    }
    fflush(stdout);
}

void app_main(void)
{
    (void)esp_read_mac(mac, ESP_MAC_WIFI_STA);
    radio_ok = radio_start();
    fem_shutdown();
    printf("{\"schema\":\"LORA-BRIDGE-BOOT-V0\",\"program\":\"bridge\",\"test_only\":true,\"idf\":\"%s\",\"radio\":%s,\"transmits_at_boot\":false,"
           "\"armed\":false,\"mac\":\"%02x%02x%02x%02x%02x%02x\"}\n",
           esp_get_idf_version(), radio_ok ? "true" : "false", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    fflush(stdout);
#if CONFIG_LORA_DISPLAY_ENABLE
    /* After the radio and the boot record; failure is logged by the component and never stops the bridge. */
    (void)lora_display_start();
    int64_t next_display_publish = 0;
#endif
    static char line[2 + 2 * 255 + 8];
    size_t used = 0;
    bool discard = false;
    unsigned idle = 0;
    for (;;) {
        /* A received packet is delivered before more console input is taken. */
        if (armed && gpio_get_level(PIN_DIO1)) {
            bridge_deliver();
        }
#if CONFIG_LORA_DISPLAY_ENABLE
        int64_t now = esp_timer_get_time();
        if (now >= next_display_publish) {
            next_display_publish = now + 1000000;
            display_publish();
        }
#endif
        int c = getchar();
        if (c == EOF) {
            clearerr(stdin);
            if (++idle >= 4) {
                vTaskDelay(1);
                idle = 0;
            }
            continue;
        }
        idle = 0;
        if (c == '\n' || c == '\r') {
            if (used && !discard) {
                line[used] = 0;
                handle(line);
            }
            used = 0;
            discard = false;
        } else if (c < 32 || c > 126 || used + 1 >= sizeof line) {
            discard = true;
        } else if (!discard) {
            line[used++] = (char)c;
        }
    }
}
