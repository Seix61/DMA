
#include "consensus/socket/server.h"

#include <ssl_socket/server/ssl_server.h>
#include <util/ssl.h>
#include <util/codec/base64.h>
#include <util/log.h>

ConsensusServer::ConsensusServer(int port) : SSLServer(port) {}

int ConsensusServer::setCertCallback(SSL *session, void *arg) {
    size_t c_size;
    std::shared_ptr<unsigned char> c_nonce;
    SSLUtil::getClientRandom(session, c_nonce, c_size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Setting client nonce for server = %s", Codec::Base64::encode(c_nonce.get(), c_size).c_str());
#endif
    size_t s_size;
    std::shared_ptr<unsigned char> s_nonce;
    SSLUtil::getServerRandom(session, s_nonce, s_size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Setting server nonce for server = %s", Codec::Base64::encode(s_nonce.get(), s_size).c_str());
#endif

    return setCert(session, arg, c_nonce.get(), c_size, s_nonce.get(), s_size);
}

int ConsensusServer::verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx) {
    return 1;
    X509 *crt = X509_STORE_CTX_get_current_cert(ctx);
    if (crt == nullptr) {
        LOG_ERROR("Failed to retrieve certificate.");
        return 0;
    }
    if (pre_verify_ok == 0) {
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            return 1;
        }
    }
    SSL *ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (ssl == nullptr) {
        LOG_ERROR("Failed to get ssl instance from X509_STORE_CTX.");
        return 0;
    }
    size_t s_size;
    std::shared_ptr<unsigned char> s_nonce;
    SSLUtil::getServerRandom(ssl, s_nonce, s_size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Getting server nonce for server = %s.", Codec::Base64::encode(s_nonce.get(), s_size).c_str());
#endif
    size_t c_size;
    std::shared_ptr<unsigned char> c_nonce;
    SSLUtil::getClientRandom(ssl, c_nonce, c_size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Getting client nonce for server = %s.", Codec::Base64::encode(c_nonce.get(), c_size).c_str());
#endif

    return verifyCert(crt, s_nonce.get(), s_size, c_nonce.get(), c_size);
}

sgx_status_t ConsensusServer::create() {
    do {
        if (SSLServer::create() != SGX_SUCCESS) {
            LOG_ERROR("Failed to create SSL server.");
            break;
        }
        if (this->setSetCertCallback(setCertCallback) != SGX_SUCCESS) {
            LOG_ERROR("Failed to set set_cert_callback.");
            break;
        }
        if (this->setVerifyCallback(verifyCallback) != SGX_SUCCESS) {
            LOG_ERROR("Failed to set verify_callback.");
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}