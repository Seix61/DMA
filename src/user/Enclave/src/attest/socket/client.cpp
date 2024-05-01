
#include "attest/socket/client.h"

#include <util/ssl.h>
#include <util/codec/base64.h>
#include <util/log.h>

AttestClient::AttestClient(int port) : SSLClient("127.0.0.1", port) {}

int AttestClient::setCertCallback(SSL *session, void *arg) {
    size_t size;
    std::shared_ptr<unsigned char> nonce;
    SSLUtil::getServerRandom(session, nonce, size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Setting server nonce for client = %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif

    return setCert(session, arg, nonce.get(), size);
}

int AttestClient::verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx) {
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
    SSLUtil::getClientRandom(ssl, nonce, size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Getting client nonce for client = %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif

    return verifyCert(crt, nonce.get(), size);
}

sgx_status_t AttestClient::create() {
    do {
        if (SSLClient::create() != SGX_SUCCESS) {
            LOG_ERROR("Failed to create SSL client.");
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
