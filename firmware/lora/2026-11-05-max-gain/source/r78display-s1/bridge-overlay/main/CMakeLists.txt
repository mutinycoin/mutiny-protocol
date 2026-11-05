idf_component_register(
    SRCS "bridge_main.c"
    PRIV_REQUIRES esp_driver_gpio esp_driver_spi esp_timer esp_hw_support esp_system esp_common freertos lora_display)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
