
#include "util_t.h"

#include <log/util.h>
#include <cstdio>

void log(LogLevel type, const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
            va_end(ap);
    switch (type) {
        case trace:
            u_log_trace(buf);
            return;
        case debug:
            u_log_debug(buf);
            break;
        case info:
            u_log_info(buf);
            break;
        case warn:
            u_log_warn(buf);
            break;
        case error:
            u_log_error(buf);
            break;
        case critical:
            u_log_critical(buf);
            break;
    }
}