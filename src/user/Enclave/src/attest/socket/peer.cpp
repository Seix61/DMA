
#include "attest/socket/peer.h"

#include <memory>
#include <util/ssl.h>
#include <util/log.h>

int AttestPeer::setCert(SSL *session, void *arg, const unsigned char *nonce, size_t nonce_size) {
    auto key = (std::shared_ptr<SSLKey> *) arg;

    do {
        std::shared_ptr<SSLX509> x509;
        SSLUtil::defaultCertInit(*key, x509);
        if (x509->sign() != SGX_SUCCESS) {
            LOG_ERROR("Failed to sign cert.");
            break;
        }
        if (!SSL_use_certificate(session, x509->getCert())) {
            LOG_ERROR("Failed to load certificate.");
            break;
        }
        if (!SSL_use_PrivateKey(session, (*key)->getPKey())) {
            LOG_ERROR("Failed to load private key on the server.");
            break;
        }
        if (!SSL_check_private_key(session)) {
            LOG_ERROR("Private key does not match the certificate.");
            break;
        }

        return 1;
    } while (false);

    return 0;
}

int AttestPeer::verifyCert(X509 *&cert, const unsigned char *nonce, size_t nonce_size) {
    do {
        auto x509 = std::make_shared<SSLX509>();
        if (x509->load(cert) != SGX_SUCCESS) {
            LOG_ERROR("Failed to load certificate.");
            break;
        }

        bool verifyResult;
        if (x509->verify(verifyResult) != SGX_SUCCESS) {
            LOG_ERROR("Failed to verify certificate.");
            break;
        }
        if (!verifyResult) {
            LOG_ERROR("Certificate invalid.");
            break;
        }

        return 1;
    } while (false);

    return 0;
}
