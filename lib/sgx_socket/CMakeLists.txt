
file(GLOB T_SRCS trusted/*.c* trusted/**/*.c*)
add_trusted_library(SGXSocketTrusted
        SRCS ${T_SRCS}
        EDL sgx_socket.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} ${SGXSSL_INCLUDE_PATH}
)

file(GLOB U_SRCS untrusted/*.c* untrusted/**/*.c*)
add_untrusted_library(SGXSocketUntrusted
        STATIC
        SRCS ${U_SRCS}
        EDL sgx_socket.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} ${SGXSSL_INCLUDE_PATH}
)