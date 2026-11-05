idf_component_register(
    SRCS "lora_display_esp.c" "lora_display_model.c" "lora_display_profile.c" "mono_fb.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_driver_i2c esp_driver_gpio freertos log
)
