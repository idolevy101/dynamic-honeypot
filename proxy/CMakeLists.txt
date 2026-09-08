cmake_minimum_required(VERSION 3.16)
project(honeypot_proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(honeypot_proxy
    src/main.cpp
    src/socket_utils.cpp
    src/proxy_server.cpp
)

target_include_directories(honeypot_proxy
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(honeypot_proxy PRIVATE _GNU_SOURCE)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(honeypot_proxy PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Werror
    )
endif()
