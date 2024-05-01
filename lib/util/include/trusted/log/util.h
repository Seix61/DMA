
#ifndef LIB_TRUSTED_LOG_UTIL_H
#define LIB_TRUSTED_LOG_UTIL_H

typedef enum {
    trace,
    debug,
    info,
    warn,
    error,
    critical
} LogLevel;

void log(LogLevel type, const char *fmt, ...);

#endif //LIB_TRUSTED_LOG_UTIL_H
