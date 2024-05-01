# FindPackage cmake file for Intel SGX SDK

cmake_minimum_required(VERSION 3.10)
include(CMakeParseArguments)

set(SGX_FOUND "NO")
set(SGXSSL_FOUND "NO")
set(SGXDCAP_FOUND "NO")

if (EXISTS SGX_DIR)
    set(SGX_PATH ${SGX_DIR})
elseif (EXISTS SGX_ROOT)
    set(SGX_PATH ${SGX_ROOT})
elseif (EXISTS $ENV{SGX_SDK})
    set(SGX_PATH $ENV{SGX_SDK})
elseif (EXISTS $ENV{SGX_DIR})
    set(SGX_PATH $ENV{SGX_DIR})
elseif (EXISTS $ENV{SGX_ROOT})
    set(SGX_PATH $ENV{SGX_ROOT})
else ()
    set(SGX_PATH "/opt/intel/sgxsdk")
endif ()

if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SGX_COMMON_CFLAGS -m32)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib32)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x86/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x86/sgx_edger8r)
else ()
    set(SGX_COMMON_CFLAGS -m64)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib64)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x64/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x64/sgx_edger8r)
endif ()

find_path(SGX_INCLUDE_DIR sgx.h "${SGX_PATH}/include" NO_DEFAULT_PATH)
find_path(SGX_LIBRARY_DIR libsgx_urts.so "${SGX_LIBRARY_PATH}" NO_DEFAULT_PATH)

if (SGX_INCLUDE_DIR AND SGX_LIBRARY_DIR)
    set(SGX_FOUND "YES")
    set(SGX_INCLUDE_DIR "${SGX_PATH}/include" CACHE PATH "Intel SGX include directory" FORCE)
    set(SGX_TLIBC_INCLUDE_DIR "${SGX_INCLUDE_DIR}/tlibc" CACHE PATH "Intel SGX tlibc include directory" FORCE)
    set(SGX_LIBCXX_INCLUDE_DIR "${SGX_INCLUDE_DIR}/libcxx" CACHE PATH "Intel SGX libcxx include directory" FORCE)
    set(SGX_INCLUDE_DIRS ${SGX_INCLUDE_DIR} ${SGX_TLIBC_INCLUDE_DIR} ${SGX_LIBCXX_INCLUDE_DIR})
    mark_as_advanced(SGX_INCLUDE_DIR SGX_TLIBC_INCLUDE_DIR SGX_LIBCXX_INCLUDE_DIR SGX_LIBRARY_DIR)
    message(STATUS "Found Intel SGX SDK: ${SGX_PATH}.")
endif ()

if (EXISTS SGXSSL_DIR)
    set(SGXSSL_PATH ${SGXSSL_DIR})
elseif (EXISTS SGXSSL_ROOT)
    set(SGXSSL_PATH ${SGXSSL_ROOT})
elseif (EXISTS $ENV{SGXSSL})
    set(SGXSSL_PATH $ENV{SGXSSL})
elseif (EXISTS $ENV{SGXSSL_DIR})
    set(SGXSSL_PATH $ENV{SGXSSL_DIR})
elseif (EXISTS $ENV{SGXSSL_ROOT})
    set(SGXSSL_PATH $ENV{SGXSSL_ROOT})
else ()
    set(SGXSSL_PATH "/opt/intel/sgxssl")
endif ()

set(SGXSSL_INCLUDE_PATH ${SGXSSL_PATH}/include)
set(SGXSSL_LIBRARY_PATH ${SGXSSL_PATH}/lib64)
find_path(SGXSSL_INCLUDE_DIR tSgxSSL_api.h "${SGXSSL_INCLUDE_PATH}" NO_DEFAULT_PATH)
find_path(SGXSSL_LIBRARY_DIR libsgx_tsgxssl.a "${SGXSSL_LIBRARY_PATH}" NO_DEFAULT_PATH)
if (SGXSSL_INCLUDE_DIR AND SGXSSL_LIBRARY_DIR)
    set(SGXSSL_FOUND "YES")
    message(STATUS "Found Intel SGX SSL: ${SGXSSL_PATH}.")
else ()
    message(STATUS "NOT found Intel SGX SSL.")
endif ()

find_library(SGXDCAP_QL_LIBRARY_PATH NAMES sgx_dcap_ql PATHS /usr)
find_library(SGXDCAP_QV_LIBRARY_PATH NAMES sgx_dcap_quoteverify PATHS /usr)
if (SGXDCAP_QL_LIBRARY_PATH AND SGXDCAP_QV_LIBRARY_PATH)
    set(SGXDCAP_FOUND "YES")
    message(STATUS "Found Intel SGX DCAP: ${SGXDCAP_QL_LIBRARY_PATH};${SGXDCAP_QV_LIBRARY_PATH}.")
else ()
    message(STATUS "NOT found Intel SGX DCAP.")
endif ()

if (SGX_FOUND)
    set(SGX_HW ON CACHE BOOL "Run SGX on hardware, OFF for simulation.")
    set(SGX_MODE PreRelease CACHE STRING "SGX build mode: Debug; PreRelease; Release.")

    if (SGX_HW)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else ()
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
    endif ()

    if (SGX_MODE STREQUAL "Debug")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g -DDEBUG -UNDEBUG -UEDEBUG")
    elseif (SGX_MODE STREQUAL "PreRelease")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -DEDEBUG")
    elseif (SGX_MODE STREQUAL "Release")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -UEDEBUG")
    else ()
        message(FATAL_ERROR "SGX_MODE ${SGX_MODE} is not Debug, PreRelease or Release.")
    endif ()
    message(STATUS "Build mode: SGX_HW: ${SGX_HW}, SGX_MODE: ${SGX_MODE}")

    set(ENCLAVE_INC_DIRS "${SGX_INCLUDE_DIR}" "${SGX_TLIBC_INCLUDE_DIR}" "${SGX_LIBCXX_INCLUDE_DIR}")
    if (SGXSSL_FOUND)
        list(APPEND ENCLAVE_INC_DIRS "${SGXSSL_INCLUDE_DIR}")
    endif ()
    if (DEFINED ADDITIONAL_ENCLAVE_INCLUDE)
        list(APPEND ENCLAVE_INC_DIRS ${ADDITIONAL_ENCLAVE_INCLUDE})
    endif ()
    message(STATUS "Trusted include: ${ENCLAVE_INC_DIRS}")
    set(ENCLAVE_C_FLAGS "${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong")
    set(ENCLAVE_CXX_FLAGS "${ENCLAVE_C_FLAGS} -nostdinc++")

    set(APP_INC_DIRS "${SGX_PATH}/include")
    if (SGXSSL_FOUND)
        list(APPEND APP_INC_DIRS "${SGXSSL_INCLUDE_DIR}")
    endif ()
    if (DEFINED ADDITIONAL_APP_INCLUDE)
        list(APPEND APP_INC_DIRS ${ADDITIONAL_APP_INCLUDE})
    endif ()
    message(STATUS "Untrusted include: ${APP_INC_DIRS}")
    set(APP_C_FLAGS "${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes ${APP_INC_FLAGS}")
    set(APP_CXX_FLAGS "${APP_C_FLAGS}")

    # build edl to *_t.h and *_t.c.
    function(_build_trusted_edl_obj edl edl_search_paths use_prefix)
        get_filename_component(EDL_NAME ${edl} NAME_WE)
        get_filename_component(EDL_ABSPATH ${edl} ABSOLUTE)
        set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
        set(EDL_T_H "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")
        set(SEARCH_PATHS "")
        foreach (path ${edl_search_paths})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach ()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        if (${SGXSSL_FOUND})
            list(APPEND SEARCH_PATHS "${SGXSSL_PATH}/include")
        endif ()
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
        if (${use_prefix})
            set(USE_PREFIX "--use-prefix")
        endif ()
        add_custom_command(OUTPUT ${EDL_T_C}
                COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                MAIN_DEPENDENCY ${EDL_ABSPATH}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(${target}-edlobj OBJECT ${EDL_T_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_T_H} ${EDL_T_C}")
    endfunction()

    # build edl to *_u.h and *_u.c.
    function(_build_untrusted_edl_obj edl edl_search_paths use_prefix)
        get_filename_component(EDL_NAME ${edl} NAME_WE)
        get_filename_component(EDL_ABSPATH ${edl} ABSOLUTE)
        set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
        set(EDL_U_H "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
        set(SEARCH_PATHS "")
        foreach (path ${edl_search_paths})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach ()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        if (${SGXSSL_FOUND})
            list(APPEND SEARCH_PATHS "${SGXSSL_PATH}/include")
        endif ()
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
        if (${use_prefix})
            set(USE_PREFIX "--use-prefix")
        endif ()
        add_custom_command(OUTPUT ${EDL_U_C}
                COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                MAIN_DEPENDENCY ${EDL_ABSPATH}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(${target}-edlobj OBJECT ${EDL_U_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${EDL_U_H} ${EDL_U_C}")
    endfunction()

    # build trusted static library to be linked into enclave library
    function(add_trusted_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if (NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif ()
        if ("${SGX_EDL}" STREQUAL "")
            message("${target}: SGX enclave edl file is not provided; skipping edger8r")
            add_library(${target} STATIC ${SGX_SRCS})
        else ()
            if ("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
                message("${target}: SGX enclave edl file search paths are not provided!")
            endif ()
            _build_trusted_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})
            add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        endif ()

        if (TRUSTED_LOG_WITH_TRACE)
            target_compile_definitions(${target} PRIVATE TRUSTED_LOG_WITH_TRACE)
        endif ()
        if (LOG_VERBOSE)
            target_compile_definitions(${target} PRIVATE LOG_VERBOSE)
        endif ()

        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})
    endfunction()

    # build enclave shared library
    function(add_enclave_library target)
        set(optionArgs USE_PREFIX USE_SGXSSL)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS TRUSTED_LIBS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if ("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif ()
        if ("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message("${target}: SGX enclave edl file search paths are not provided!")
        endif ()
        if (NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif ()

        _build_trusted_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})

        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})

        # add link libs
        set(LINK_LIBRARY_PATHS ${SGX_LIBRARY_PATH})
        set(FORCE_LINK_LIBS ${SGX_TRTS_LIB})
        set(GROUP_LINK_LIBS sgx_tstdc sgx_pthread sgx_tcxx sgx_tkey_exchange sgx_tcrypto ${SGX_TSVC_LIB})
        if (${SGX_USE_SGXSSL})
            if (NOT ${SGXSSL_FOUND})
                message(FATAL_ERROR "SGX SSL not found, cannot build library with USE_SGXSSL")
            endif ()
            list(APPEND LINK_LIBRARY_PATHS ${SGXSSL_LIBRARY_PATH})
            list(APPEND FORCE_LINK_LIBS sgx_tsgxssl)
            list(APPEND GROUP_LINK_LIBS sgx_tsgxssl_ssl sgx_tsgxssl_crypto sgx_ttls)
            target_include_directories(${target} PRIVATE ${SGXSSL_INCLUDE_PATH})
        endif ()

        # build link flags
        set(TLIB_PATH_LIST "")
        foreach (ITEM ${LINK_LIBRARY_PATHS})
            string(APPEND TLIB_PATH_LIST "-L${ITEM} ")
        endforeach ()
        set(FORCE_TLIB_LIST "")
        foreach (ITEM ${FORCE_LINK_LIBS})
            string(APPEND FORCE_TLIB_LIST "-l${ITEM} ")
        endforeach ()
        set(TLIB_LIST "")
        foreach (ITEM ${SGX_TRUSTED_LIBS})
            string(APPEND TLIB_LIST "$<TARGET_FILE:${ITEM}> ")
            add_dependencies(${target} ${ITEM})
        endforeach ()
        foreach (ITEM ${GROUP_LINK_LIBS})
            string(APPEND TLIB_LIST "-l${ITEM} ")
        endforeach ()

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles ${TLIB_PATH_LIST} \
                -Wl,--whole-archive ${FORCE_TLIB_LIST} -Wl,--no-whole-archive \
                -Wl,--start-group ${TLIB_LIST} -Wl,--end-group \
                -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
                ${LDSCRIPT_FLAG} \
                -Wl,--defsym,__ImageBase=0")

        # add external compile definitions
        if (TRUSTED_LOG_WITH_TRACE)
            target_compile_definitions(${target} PRIVATE TRUSTED_LOG_WITH_TRACE)
        endif ()
        if (LOG_VERBOSE)
            target_compile_definitions(${target} PRIVATE LOG_VERBOSE)
        endif ()
    endfunction()

    # sign the enclave, according to configurations one-step or two-step signing will be performed.
    # default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
    function(enclave_sign target)
        set(optionArgs IGNORE_INIT IGNORE_REL)
        set(oneValueArgs KEY CONFIG OUTPUT)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "" ${ARGN})
        if ("${SGX_CONFIG}" STREQUAL "")
            message("${target}: SGX enclave config is not provided!")
        else ()
            get_filename_component(CONFIG_ABSPATH ${SGX_CONFIG} ABSOLUTE)
        endif ()
        if ("${SGX_KEY}" STREQUAL "")
            if (NOT SGX_HW OR NOT SGX_MODE STREQUAL "Release")
                message(FATAL_ERROR "${target}: Private key used to sign enclave is not provided!")
            endif ()
        else ()
            get_filename_component(KEY_ABSPATH ${SGX_KEY} ABSOLUTE)
        endif ()
        if ("${SGX_OUTPUT}" STREQUAL "")
            set(OUTPUT_NAME "${target}.signed.so")
        else ()
            set(OUTPUT_NAME ${SGX_OUTPUT})
        endif ()
        if (${SGX_IGNORE_INIT})
            set(IGN_INIT "-ignore-init-sec-error")
        endif ()
        if (${SGX_IGNORE_REL})
            set(IGN_REL "-ignore-rel-error")
        endif ()

        if (SGX_HW AND SGX_MODE STREQUAL "Release")
            add_custom_target(${target}-sign ALL
                    COMMAND ${SGX_ENCLAVE_SIGNER} gendata
                    $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                    -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${target}_hash.hex ${IGN_INIT} ${IGN_REL}
                    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                    --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/${target}_hash.hex for second step"
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        else ()
            add_custom_target(${target}-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${KEY_ABSPATH}
                    $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                    -enclave $<TARGET_FILE:${target}>
                    -out $<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME}
                    ${IGN_INIT} ${IGN_REL}
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        endif ()

        set(CLEAN_FILES "$<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME};$<TARGET_FILE_DIR:${target}>/${target}_hash.hex")
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")
    endfunction()

    # build untrusted static library to be linked into executable program
    function(add_untrusted_library target mode)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL)
        set(multiValueArgs SRCS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if ("${SGX_EDL}" STREQUAL "")
            message("${target}: SGX enclave edl file is not provided; skipping edger8r")
            add_library(${target} STATIC ${SGX_SRCS})
        else ()
            if ("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
                message("${target}: SGX enclave edl file search paths are not provided!")
            endif ()
            _build_untrusted_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})
            add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        endif ()

        if (LOG_VERBOSE)
            target_compile_definitions(${target} PRIVATE LOG_VERBOSE)
        endif ()

        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})
    endfunction()

    # build executable program
    function(add_untrusted_executable target)
        set(optionArgs USE_PREFIX USE_SGXSSL)
        set(oneValueArgs EDL)
        set(multiValueArgs SRCS UNTRUSTED_LIBS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if ("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif ()
        if ("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message("${target}: SGX enclave edl file search paths are not provided!")
        endif ()

        _build_untrusted_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})

        add_executable(${target} ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})

        # add link libs
        set(LINK_LIBRARY_PATHS ${SGX_LIBRARY_PATH})
        set(FORCE_LINK_LIBS ${SGX_URTS_LIB})
        set(GROUP_LINK_LIBS curl ssl sgx_ukey_exchange pthread crypto ${SGX_USVC_LIB})
        if (${SGX_USE_SGXSSL})
            if (NOT ${SGXSSL_FOUND})
                message(FATAL_ERROR "SGX SSL not found, cannot build library with USE_SGXSSL")
            endif ()
            if (NOT ${SGXDCAP_FOUND})
                message(FATAL_ERROR "SGX DCAP not found, cannot build library with USE_SGXSSL")
            endif ()
            list(APPEND LINK_LIBRARY_PATHS ${SGXSSL_LIBRARY_PATH})
            list(APPEND FORCE_LINK_LIBS sgx_usgxssl)
            list(APPEND GROUP_LINK_LIBS sgx_utls sgx_dcap_ql sgx_dcap_quoteverify)
            target_include_directories(${target} PRIVATE ${SGXSSL_INCLUDE_PATH})
        endif ()

        # build link flags
        set(ULIB_PATH_LIST "")
        foreach (ITEM ${LINK_LIBRARY_PATHS})
            string(APPEND ULIB_PATH_LIST "-L${ITEM} ")
        endforeach ()
        set(FORCE_ULIB_LIST "")
        foreach (ITEM ${FORCE_LINK_LIBS})
            string(APPEND FORCE_ULIB_LIST "-l${ITEM} ")
        endforeach ()
        set(ULIB_LIST "")
        foreach (ITEM ${SGX_UNTRUSTED_LIBS})
            string(APPEND ULIB_LIST "$<TARGET_FILE:${ITEM}> ")
            add_dependencies(${target} ${ITEM})
        endforeach ()
        foreach (ITEM ${GROUP_LINK_LIBS})
            string(APPEND ULIB_LIST "-l${ITEM} ")
        endforeach ()

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                ${ULIB_PATH_LIST} \
                -Wl,--whole-archive ${FORCE_ULIB_LIST} -Wl,--no-whole-archive \
                -Wl,--start-group ${ULIB_LIST} -Wl,--end-group")

        # add external compile definitions
        if (LOG_VERBOSE)
            target_compile_definitions(${target} PRIVATE LOG_VERBOSE)
        endif ()
    endfunction()

else (SGX_FOUND)
    message(WARNING "Intel SGX SDK not found!")
    if (SGX_FIND_REQUIRED)
        message(FATAL_ERROR "Could NOT find Intel SGX SDK!")
    endif ()
endif (SGX_FOUND)