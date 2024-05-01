
file(GLOB_RECURSE ENCLAVE_SRCS Enclave/**/*.c*)
add_enclave_library(AttestEnclave
        SRCS ${ENCLAVE_SRCS}
        TRUSTED_LIBS SSLSocketTrusted SGXSocketTrusted UtilTrusted AttestationTrusted SchedulerTrusted ipp_math common verifier tinymath member_tiny EPIDTrusted
        USE_SGXSSL
        EDL Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
        LDSCRIPT Enclave.lds
)
target_include_directories(AttestEnclave PRIVATE Enclave/include)
enclave_sign(AttestEnclave
        OUTPUT enclave.signed.so
        KEY Enclave_private_test.pem
        CONFIG Enclave.config.xml
)

file(GLOB_RECURSE APP_SRCS App/**/*.c*)
add_untrusted_executable(AttestApp
        SRCS ${APP_SRCS}
        UNTRUSTED_LIBS SGXSocketUntrusted UtilUntrusted AttestationUntrusted SchedulerUntrusted jsoncpp_static
        USE_SGXSSL
        EDL Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)
target_include_directories(AttestApp PRIVATE App/include)

add_dependencies(AttestApp AttestEnclave-sign)