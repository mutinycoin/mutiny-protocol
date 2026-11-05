cmake_minimum_required(VERSION 3.16)

# Bench packet bridge. Never invoke a flash or monitor target here.
set(COMPONENTS main)
# Display overlay: the status OLED component lives beside this project.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components/lora_display")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(mutiny_lora_bridge_display)
