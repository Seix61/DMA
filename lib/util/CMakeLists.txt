
file(GLOB T_SRCS trusted/*.c* trusted/**/*.c* global/*.c* global/**/*.c*)
add_trusted_library(UtilTrusted
        SRCS ${T_SRCS}
        EDL util.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} ${SGXSSL_INCLUDE_PATH}
)

file(GLOB U_SRCS untrusted/*.c* untrusted/**/*.c* global/*.c* global/**/*.c*)
add_untrusted_library(UtilUntrusted
        STATIC
        SRCS ${U_SRCS}
        EDL util.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} ${SGXSSL_INCLUDE_PATH}
)