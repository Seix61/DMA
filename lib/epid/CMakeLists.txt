
file(GLOB T_SRCS trusted/*.c* trusted/**/*.c*)
add_trusted_library(EPIDTrusted
        SRCS ${T_SRCS}
)