
#include "sgx_urts.h"
#include "Enclave_u.h"

#include <csignal>
#include <sstream>
#include <util/log.h>
#include <util/break.h>

#include <CLI/CLI.hpp>

# define ENCLAVE_FILENAME "enclave.signed.so"
# define TOKEN_FILENAME   "enclave.token"

sgx_enclave_id_t global_enclave_id;

void ignore_sigpipe() {
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, nullptr);
}

int SGX_CDECL main(int argc, char *argv[]) {
    ignore_sigpipe();

    CLI::App app;

    int attestConnect;
    app.add_option("-a,--attest_connect", attestConnect, "Port connecting for AttestRole")->required();

    int userNodeId;
    app.add_option("-i,--user_node_id", userNodeId, "Node id for UserRole")->required();

    int userListen;
    app.add_option("-u,--user_listen", userListen, "Port listening for UserRole")->required();

    std::vector<std::string> peers;
    app.add_option("-p,--peers", peers, "Peer addresses for UserRole")->required();

    app.set_config("--config", "", "Configs from file", false);
    CLI11_PARSE(app, argc, argv);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("%^[%H:%M:%S.%f] @ %t [%L]%$ %v");

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, nullptr, nullptr, &global_enclave_id, nullptr);
    RETURN_ON_CREATE_FAILED(ret, ENCLAVE_FILENAME, global_enclave_id);

    size_t peerCount = peers.size();
    std::ostringstream oss;
    oss.write((char *)&peerCount, sizeof(size_t));
    for (const auto &item : peers) {
        size_t length = item.length();
        oss.write((char *)&length, sizeof(size_t));
        oss.write(item.c_str(), length);
    }
    std::string peerStruct = oss.str();
    size_t peerStructSize = peerStruct.size();
    const char *peerStructChars = peerStruct.c_str();

    int call_ret = ecall_launch_user_node(global_enclave_id,
                                          attestConnect,
                                          userNodeId,
                                          userListen,
                                          peerStructSize,
                                          peerStructChars);
    RETURN_ON_ERROR("ecall_launch_user_node", call_ret, -1);

    while (true) {}

    sgx_destroy_enclave(global_enclave_id);
    return 0;
}