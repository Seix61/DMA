
#ifndef LIB_TRUSTED_UTIL_LOG_H
#define LIB_TRUSTED_UTIL_LOG_H

#include <log/util.h>

#define LOG_TRACE_WITH_TRACE(fmt, ...) \
    log(LogLevel::trace, "[%s#L%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_TRACE_WITHOUT_TRACE(fmt, ...) \
    log(LogLevel::trace, fmt, ##__VA_ARGS__)

#define LOG_DEBUG_WITH_TRACE(fmt, ...) \
    log(LogLevel::debug, "[%s#L%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG_WITHOUT_TRACE(fmt, ...) \
    log(LogLevel::debug, fmt, ##__VA_ARGS__)

#define LOG_INFO_WITH_TRACE(fmt, ...) \
    log(LogLevel::info, "[%s#L%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_INFO_WITHOUT_TRACE(fmt, ...) \
    log(LogLevel::info, fmt, ##__VA_ARGS__)

#define LOG_WARN_WITH_TRACE(fmt, ...) \
    log(LogLevel::warn, "[%s#L%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN_WITHOUT_TRACE(fmt, ...) \
    log(LogLevel::warn, fmt, ##__VA_ARGS__)

#define LOG_ERROR_WITH_TRACE(fmt, ...) \
    log(LogLevel::error, "[%s#L%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR_WITHOUT_TRACE(fmt, ...) \
    log(LogLevel::error, fmt, ##__VA_ARGS__)

#define LOG_CRITICAL_WITH_TRACE(fmt, ...) \
    log(LogLevel::critical, "[%s#L%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_CRITICAL_WITHOUT_TRACE(fmt, ...) \
    log(LogLevel::critical, fmt, ##__VA_ARGS__)

#ifdef TRUSTED_LOG_WITH_TRACE
#define LOG_TRACE(fmt, ...) \
    LOG_TRACE_WITH_TRACE(fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) \
    LOG_DEBUG_WITH_TRACE(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) \
    LOG_INFO_WITH_TRACE(fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) \
    LOG_WARN_WITH_TRACE(fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    LOG_ERROR_WITH_TRACE(fmt, ##__VA_ARGS__)
#define LOG_CRITICAL(fmt, ...) \
    LOG_CRITICAL_WITH_TRACE(fmt, ##__VA_ARGS__)
#else
#define LOG_TRACE(fmt, ...) \
    LOG_TRACE_WITHOUT_TRACE(fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) \
    LOG_DEBUG_WITHOUT_TRACE(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) \
    LOG_INFO_WITHOUT_TRACE(fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) \
    LOG_WARN_WITHOUT_TRACE(fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    LOG_ERROR_WITHOUT_TRACE(fmt, ##__VA_ARGS__)
#define LOG_CRITICAL(fmt, ...) \
    LOG_CRITICAL_WITHOUT_TRACE(fmt, ##__VA_ARGS__)
#endif

#endif //LIB_TRUSTED_UTIL_LOG_H
