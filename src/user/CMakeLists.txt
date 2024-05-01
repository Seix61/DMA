
file(GLOB_RECURSE ENCLAVE_SRCS Enclave/**/*.c*)
add_enclave_library(UserEnclave
        SRCS ${ENCLAVE_SRCS}
        TRUSTED_LIBS SSLSocketTrusted SGXSocketTrusted UtilTrusted SchedulerTrusted AttestationTrusted
        USE_SGXSSL
        EDL Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
        LDSCRIPT Enclave.lds
)
target_include_directories(UserEnclave PRIVATE Enclave/include)
enclave_sign(UserEnclave
        OUTPUT enclave.signed.so
        KEY Enclave_private_test.pem
        CONFIG Enclave.config.xml
)

file(GLOB_RECURSE APP_SRCS App/**/*.c*)
add_untrusted_executable(UserApp
        SRCS ${APP_SRCS}
        UNTRUSTED_LIBS SGXSocketUntrusted UtilUntrusted SchedulerUntrusted AttestationUntrusted jsoncpp_static
        USE_SGXSSL
        EDL Enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)
target_include_directories(UserApp PRIVATE App/include)

add_dependencies(UserApp UserEnclave-sign)