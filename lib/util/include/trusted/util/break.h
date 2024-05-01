
#ifndef LIB_TRUSTED_UTIL_BREAK_H
#define LIB_TRUSTED_UTIL_BREAK_H

#include <util/log.h>

#define BREAK_ON_ERROR(func_name, call_ret)                                 \
    if (call_ret != 0) {                                                    \
        LOG_ERROR("Failed to %s. Call return 0x%X.", func_name, call_ret);  \
        break;                                                              \
    }                                                                       \
    LOG_INFO("Succeed to %s.", func_name);

#define BREAK_ON_ERROR_EX(func_name, call_ret, func_ret)                                                \
    if (call_ret != 0) {                                                                                \
        LOG_ERROR("Failed to %s. Call return 0x%X. Func return 0x%X.", func_name, call_ret, func_ret);  \
        break;                                                                                          \
    }                                                                                                   \
    LOG_INFO("Succeed to %s.", func_name);

#define RETURN_ON_ERROR(func_name, call_ret, ret)                           \
    if (call_ret != 0) {                                                    \
        LOG_ERROR("Failed to %s. Call return 0x%X.", func_name, call_ret);  \
        return ret;                                                         \
    }                                                                       \
    LOG_INFO("Succeed to %s.", func_name);

#define RETURN_ON_ERROR_EX(func_name, call_ret, func_ret, ret)                                          \
    if (call_ret != 0 || func_ret != 0) {                                                               \
        LOG_ERROR("Failed to %s. Call return 0x%X. Func return 0x%X.", func_name, call_ret, func_ret);  \
        return ret;                                                                                     \
    }                                                                                                   \
    LOG_INFO("Succeed to %s.", func_name);

#endif //LIB_TRUSTED_UTIL_BREAK_H
