cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_present_project C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()
add_executable(pico-gpio
  main.c
)

pico_enable_stdio_usb(pico-gpio 1)
pico_enable_stdio_uart(pico-gpio 1)
pico_add_extra_outputs(pico-gpio)
target_link_libraries(pico-gpio pico_stdlib hardware_clocks pico_time hardware_i2c hardware_flash hardware_sync hardware_adc pico_multicore)

