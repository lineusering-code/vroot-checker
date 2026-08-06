cmake_minimum_required(VERSION 3.22.1)

project("vroot")

add_library(vroot SHARED vroot_native.c)

find_library(log-lib log)

target_compile_options(vroot PRIVATE
        -Wall
        -Wno-unused-parameter
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections)

target_link_libraries(vroot ${log-lib})
