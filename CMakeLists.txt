
cmake_minimum_required(VERSION 3.10)
project(DMA)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SGX_HW ON)
set(SGX_MODE "Debug")
set(TRUSTED_LOG_WITH_TRACE ON)
set(LOG_VERBOSE OFF)

file(GLOB ADDITIONAL_ENCLAVE_INCLUDE
        ${CMAKE_SOURCE_DIR}/3rd-party/epid-sdk/epid/**/include
        ${CMAKE_SOURCE_DIR}/3rd-party/epid-sdk/epid/internal/**/include
        ${CMAKE_SOURCE_DIR}/lib/*/include/global
        ${CMAKE_SOURCE_DIR}/lib/*/include/trusted
        ${CMAKE_SOURCE_DIR}/include/global
        ${CMAKE_SOURCE_DIR}/include/trusted
)
file(GLOB ADDITIONAL_APP_INCLUDE
        ${CMAKE_SOURCE_DIR}/3rd-party/spdlog/include
        ${CMAKE_SOURCE_DIR}/3rd-party/CLI11/include
        ${CMAKE_SOURCE_DIR}/3rd-party/jsoncpp/include
        ${CMAKE_SOURCE_DIR}/lib/*/include/global
        ${CMAKE_SOURCE_DIR}/lib/*/include/untrusted
        ${CMAKE_SOURCE_DIR}/include/global
        ${CMAKE_SOURCE_DIR}/include/untrusted
)

find_package(SGX REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

set(EDL_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/lib)

add_subdirectory(lib)
add_subdirectory(src)
add_subdirectory(3rd-party/spdlog)
add_subdirectory(3rd-party/epid-sdk)
add_subdirectory(3rd-party/CLI11)
add_subdirectory(3rd-party/jsoncpp)
