
#ifndef LIB_UNTRUSTED_UTIL_BREAK_H
#define LIB_UNTRUSTED_UTIL_BREAK_H

#include <util/log.h>

#define BREAK_ON_CREATE_FAILED(sgx_ret, file, id)                               \
    if (sgx_ret != 0) {                                                         \
        spdlog::error("Failed to load {}. Call return 0x{:X}.", file, sgx_ret); \
        break;                                                                  \
    }                                                                           \
    spdlog::info("Succeed to load {}, id: {}.", file, id);

#define RETURN_ON_CREATE_FAILED(sgx_ret, file, id)                              \
    if (sgx_ret != 0) {                                                         \
        spdlog::error("Failed to load {}. Call return 0x{:X}.", file, sgx_ret); \
        return -1;                                                              \
    }                                                                           \
    spdlog::info("Succeed to load {}, id: {}.", file, id);

#define BREAK_ON_ERROR(func_name, call_ret)                                         \
    if (call_ret != 0) {                                                            \
        spdlog::error("Failed to {}. Call return 0x{:X}.", func_name, call_ret);    \
        break;                                                                      \
    }                                                                               \
    spdlog::info("Succeed to {}.", func_name);

#define BREAK_ON_ERROR_EX(func_name, call_ret, func_ret)                                                        \
    if (call_ret != 0) {                                                                                        \
        spdlog::error("Failed to {}. Call return 0x{:X}. Func return 0x{:X}.", func_name, call_ret, func_ret);  \
        break;                                                                                                  \
    }                                                                                                           \
    spdlog::info("Succeed to {}.", func_name);

#define RETURN_ON_ERROR(func_name, call_ret, ret)                                   \
    if (call_ret != 0) {                                                            \
        spdlog::error("Failed to {}. Call return 0x{:X}.", func_name, call_ret);    \
        return ret;                                                                 \
    }                                                                               \
    spdlog::info("Succeed to {}.", func_name);

#define RETURN_ON_ERROR_EX(func_name, call_ret, func_ret, ret)                                                  \
    if (call_ret != 0 || func_ret != 0) {                                                                       \
        spdlog::error("Failed to {}. Call return 0x{:X}. Func return 0x{:X}.", func_name, call_ret, func_ret);  \
        return ret;                                                                                             \
    }                                                                                                           \
    spdlog::info("Succeed to {}.", func_name);

#endif //LIB_UNTRUSTED_UTIL_BREAK_H
