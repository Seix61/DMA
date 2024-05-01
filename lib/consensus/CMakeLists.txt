
file(GLOB T_SRCS trusted/*.c* trusted/**/*.c*)
add_trusted_library(ConsensusTrusted
        SRCS ${T_SRCS}
)