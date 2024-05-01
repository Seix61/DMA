
#include <ssl_socket/peer/ssl_peer.h>
#include <ssl_socket/define.h>
#include <util/ssl.h>
#include <util/codec/base64.h>
#include <util/log.h>

SSLPeer::SSLPeer(const SSL_METHOD *(*method)()) : key(std::make_shared<SSLKey>()),
                                                  context(std::make_shared<SSLContext>(method)) {}

sgx_status_t SSLPeer::create() {
    do {
        if (this->key->generate() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to generate SSL key.");
#endif
            break;
        }
        if (this->context->create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create SSL context.");
#endif
            break;
        }
        this->setSetCertCallback(defaultSetCertCallback);

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLPeer::setSetCertCallback(int (*callback)(SSL *, void *)) {
    do {
        if (this->context->setSetCertCallback(callback, &this->key) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set cert callback.");
#endif
            break;
        }
        return SGX_SUCCESS;
    } while (false);
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLPeer::setVerifyCallback(int (*callback)(int, X509_STORE_CTX *)) {
    this->certVerifyCallback = callback;
    return SGX_SUCCESS;
}

sgx_status_t SSLPeer::setErrorCallback(std::function<void(std::shared_ptr<SSLSession>, int)> callback) {
    this->errorCallback = std::move(callback);
    return SGX_SUCCESS;
}

sgx_status_t SSLPeer::setBeforeHandshakeHandler(std::function<void(int)> handler) {
    this->beforeHandshakeHandler = std::move(handler);
    return SGX_SUCCESS;
}

sgx_status_t SSLPeer::setAfterHandshakeHandler(std::function<void(int)> handler) {
    this->afterHandshakeHandler = std::move(handler);
    return SGX_SUCCESS;
}

int SSLPeer::defaultSetCertCallback(SSL *session, void *arg) {
    auto key = (std::shared_ptr<SSLKey> *) arg;

    LOG_WARN("default_set_cert_callback called.");

    size_t size;
    std::shared_ptr<unsigned char> nonce;
    SSLUtil::getServerRandom(session, nonce, size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Server nonce is %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif
    SSLUtil::getClientRandom(session, nonce, size);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Client nonce is %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif

    do {
        std::shared_ptr<SSLX509> x509;
        SSLUtil::defaultCertInit(*key, x509);
        const char *buffer = "Hello";
        size_t bufferSize = strlen(buffer) + 1;
        if (x509->addCostumeExtension(OID_FOR_QUOTE_STRING, (uint8_t *) buffer, bufferSize) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to add extension into cert.");
#endif
            break;
        }
        if (x509->sign() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to sign cert.");
#endif
            break;
        }
        if (!SSL_use_certificate(session, x509->getCert())) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to load certificate.");
#endif
            break;
        }
        if (!SSL_use_PrivateKey(session, (*key)->getPKey())) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to load private key on the server.");
#endif
            break;
        }
        if (!SSL_check_private_key(session)) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Private key does not match the certificate.");
#endif
            break;
        }

        return 1;
    } while (false);

    return 0;
}

int SSLPeer::defaultVerifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx) {
    int ret = 0;
    int err = X509_V_ERR_UNSPECIFIED;
    X509 *crt;
    SSL *ssl;

    LOG_WARN("default_verify_callback called with pre_verify_ok = %d.", pre_verify_ok);

    do {
        if ((crt = X509_STORE_CTX_get_current_cert(ctx)) == nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to retrieve certificate.");
#endif
            break;
        }

        if (pre_verify_ok == 0) {
            err = X509_STORE_CTX_get_error(ctx);
#ifdef LOG_VERBOSE
            LOG_WARN("X.509 verify with error = %d", err);
#endif
            if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
                ret = 1;
                break;
            }
        }

        auto x509 = std::make_shared<SSLX509>();
        if (x509->load(crt) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to load certificate.");
#endif
            break;
        }
        bool verifyResult;
        if (x509->verify(verifyResult) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to verify certificate.");
#endif
            break;
        }
        if (!verifyResult) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Certificate invalid.");
#endif
            break;
        }

        size_t size;
        std::shared_ptr<uint8_t> buffer;
        if (x509->getCostumeExtension(OID_FOR_QUOTE_STRING, buffer, size) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to get costume extension from certificate.");
#endif
            break;
        }
#ifdef LOG_VERBOSE
        LOG_INFO("Extension buffer read = %s", buffer.get());
#endif
        if ((ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx())) == nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to get ssl instance from X509_STORE_CTX.");
#endif
            break;
        }
        std::shared_ptr<unsigned char> nonce;
        SSLUtil::getServerRandom(ssl, nonce, size);
#ifdef LOG_VERBOSE
        LOG_DEBUG("Server nonce is %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif
        SSLUtil::getClientRandom(ssl, nonce, size);
#ifdef LOG_VERBOSE
        LOG_DEBUG("Client nonce is %s.", Codec::Base64::encode(nonce.get(), size).c_str());
#endif

        ret = 1;
    } while (false);

    return ret;
}
