
file(GLOB T_SRCS trusted/*.c* trusted/**/*.c*)
add_trusted_library(SSLSocketTrusted
        SRCS ${T_SRCS}
)

add_dependencies(SSLSocketTrusted SGXSocketTrusted)