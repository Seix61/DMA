
file(GLOB_RECURSE ENCLAVE_SRCS Enclave/**/*.c*)
add_enclave_library(AuthEnclave
        SRCS ${ENCLAVE_SRCS}
        TRUSTED_LIBS SSLSocketTrusted SGXSocketTrusted UtilTrusted AttestationTrusted SchedulerTrusted ConsensusTrusted ipp_math common EPIDTrusted
        USE_SGXSSL
        EDL Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
        LDSCRIPT Enclave.lds
)
target_include_directories(AuthEnclave PRIVATE Enclave/include)
enclave_sign(AuthEnclave
        OUTPUT enclave.signed.so
        KEY Enclave_private_test.pem
        CONFIG Enclave.config.xml
)

file(GLOB_RECURSE APP_SRCS App/**/*.c*)
add_untrusted_executable(AuthApp
        SRCS ${APP_SRCS}
        UNTRUSTED_LIBS SGXSocketUntrusted UtilUntrusted AttestationUntrusted SchedulerUntrusted jsoncpp_static
        USE_SGXSSL
        EDL Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)
target_include_directories(AuthApp PRIVATE App/include)

add_dependencies(AuthApp AuthEnclave-sign)