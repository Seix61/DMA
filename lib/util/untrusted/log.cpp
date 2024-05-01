
#include "util_u.h"

#include <util/log.h>

void u_log_trace(const char *str) {
    spdlog::trace(str);
}

void u_log_debug(const char *str) {
    spdlog::debug(str);
}

void u_log_info(const char *str) {
    spdlog::info(str);
}

void u_log_warn(const char *str) {
    spdlog::warn(str);
}

void u_log_error(const char *str) {
    spdlog::error(str);
}

void u_log_critical(const char *str) {
    spdlog::critical(str);
}
