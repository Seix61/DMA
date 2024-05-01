
file(GLOB T_SRCS trusted/*.c* trusted/**/*.c*)
add_trusted_library(SchedulerTrusted
        SRCS ${T_SRCS}
        EDL scheduler.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} ${SGXSSL_INCLUDE_PATH}
)

file(GLOB U_SRCS untrusted/*.c* untrusted/**/*.c*)
add_untrusted_library(SchedulerUntrusted
        STATIC
        SRCS ${U_SRCS}
        EDL scheduler.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} ${SGXSSL_INCLUDE_PATH}
)