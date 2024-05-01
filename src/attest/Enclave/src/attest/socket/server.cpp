
#include "attest/socket/server.h"

#include <util/ssl.h>
#include <util/codec/base64.h>
#include <util/log.h>

AttestServer::AttestServer(int port) : SSLServer(port) {}

int AttestServer::setCertCallback(SSL *session, void *arg) {
    size_t size;
    std::shared_ptr<unsigned char> nonce;
    SSLUtil::getClientRandom(session, nonce, size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Setting client nonce for server = %s", Codec::Base64::encode(nonce.get(), size).c_str());
#endif

    return setCert(session, arg, nonce.get(), size);
}

int AttestServer::verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx) {
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
    size_t size;
    std::shared_ptr<unsigned char> nonce;
    SSLUtil::getServerRandom(ssl, nonce, size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Getting server nonce for server = %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif

    return verifyCert(crt, nonce.get(), size);
}

sgx_status_t AttestServer::create() {
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
