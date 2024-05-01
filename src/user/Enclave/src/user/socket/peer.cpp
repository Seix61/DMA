
#include "api.h"
#include "user/socket/peer.h"

#include <memory>
#include <sgx_tcrypto.h>
#include <ssl_socket/define.h>
#include <util/ssl.h>
#include <util/codec/base64.h>
#include <util/memory.h>
#include <util/log.h>

int UserPeer::setCert(SSL *session, void *arg, const unsigned char *peer_nonce, size_t peer_nonce_size,
                      const unsigned char *self_nonce, size_t self_nonce_size) {
    auto key = (std::shared_ptr<SSLKey> *) arg;

    do {
        std::shared_ptr<SSLX509> x509;
        SSLUtil::defaultCertInit(*key, x509);

        uint8_t *pub = nullptr;
        size_t pub_size;
        if (x509->getPublicKeyInPEM(pub, &pub_size) != SGX_SUCCESS) {
            LOG_ERROR("Failed to get public key.");
            break;
        }
#ifdef LOG_VERBOSE
        LOG_DEBUG("PUB = %s", std::string((char *)pub, pub_size).c_str());
#endif

        sgx_sha256_hash_t userData;
        sgx_sha_state_handle_t sha_handle;
        if (sgx_sha256_init(&sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_init.");
            break;
        }
        if (sgx_sha256_update((uint8_t *)peer_nonce, peer_nonce_size, sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_update.");
            break;
        }
        if (sgx_sha256_update((uint8_t *)self_nonce, self_nonce_size, sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_update.");
            break;
        }
        if (sgx_sha256_update((uint8_t *)pub, pub_size, sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_update.");
            break;
        }
        if (sgx_sha256_get_hash(sha_handle, &userData) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_get_hash.");
            break;
        }
        if (sha_handle != nullptr) {
            sgx_sha256_close(sha_handle);
        }
        delete pub;

#ifdef LOG_VERBOSE
        LOG_INFO("Setting UserData = %s", Codec::Base64::encode((const char *) &userData, sizeof(userData)).c_str());
#endif
        std::shared_ptr<dma_quote> quote;
        size_t quoteSize;
        LOG_DEBUG("Before_create_quote.");
        create_quote(userData, sizeof(sgx_sha256_hash_t), quote, quoteSize);
        LOG_DEBUG("After_create_quote.");
        if (quote == nullptr) {
            LOG_ERROR("Failed to get self quote.");
            break;
        }
//        LOG_DEBUG("set QUOTE.sig = %s", Codec::Base64::encode(quote->signature, quote->signature_len).c_str());
#ifdef LOG_VERBOSE
        LOG_DEBUG("quote = %s", Codec::Base64::encode((char *)quote.get(), quoteSize).c_str());
#endif
        if (x509->addCostumeExtension(OID_FOR_QUOTE_STRING, (uint8_t *) quote.get(), quoteSize) != SGX_SUCCESS) {
            LOG_ERROR("Failed to add extension into cert.");
            break;
        }

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

int UserPeer::verifyCert(X509 *&cert, const unsigned char *self_nonce, size_t self_nonce_size,
                         const unsigned char *peer_nonce,
                         size_t peer_nonce_size, int socketFd) {
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

        uint8_t *pub = nullptr;
        size_t pub_size;
        if (x509->getPublicKeyInPEM(pub, &pub_size) != SGX_SUCCESS) {
            LOG_ERROR("Failed to get public key.");
            break;
        }
#ifdef LOG_VERBOSE
        LOG_DEBUG("PUB = %s", std::string((char *)pub, pub_size).c_str());
#endif

        size_t quote_size;
        std::shared_ptr<uint8_t> quote_buffer;
        if (x509->getCostumeExtension(OID_FOR_QUOTE_STRING, quote_buffer, quote_size) != SGX_SUCCESS) {
            LOG_ERROR("Failed to get costume extension from certificate.");
            break;
        }

        sgx_sha256_hash_t userData;
        sgx_sha_state_handle_t sha_handle;
        if (sgx_sha256_init(&sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_init.");
            break;
        }
        if (sgx_sha256_update((uint8_t *)self_nonce, peer_nonce_size, sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_update.");
            break;
        }
        if (sgx_sha256_update((uint8_t *)peer_nonce, self_nonce_size, sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_update.");
            break;
        }
        if (sgx_sha256_update((uint8_t *)pub, pub_size, sha_handle) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_update.");
            break;
        }
        if (sgx_sha256_get_hash(sha_handle, &userData) != SGX_SUCCESS) {
            LOG_ERROR("Failed to sgx_sha256_get_hash.");
            break;
        }
        if (sha_handle != nullptr) {
            sgx_sha256_close(sha_handle);
        }
        delete pub;

        auto report_data = ((dma_quote *) quote_buffer.get())->report_body.report_data;
#ifdef LOG_VERBOSE
        LOG_INFO("Verifying UserData = %s, Recalculate = %s", Codec::Base64::encode((const char *) &report_data).c_str(), Codec::Base64::encode((const char *) &userData).c_str());
#endif
        if (memcmp(&report_data, &userData, sizeof(sgx_sha256_hash_t)) != 0) {
            LOG_ERROR("UserData not match.");
            break;
        }

        auto quote = Memory::copyOf<uint8_t, dma_quote>(quote_buffer, quote_size);
//        LOG_DEBUG("get QUOTE.sig = %s", Codec::Base64::encode(quote->signature, quote->signature_len).c_str());
        bool result = false;
        LOG_DEBUG("Before_verify_quote.");
        verify_quote(quote, quote_size, result);
        LOG_DEBUG("After_verify_quote.");
        LOG_INFO("Verify result = %d, platformStatus = %d", result, quote->platform_status);

        if (result) {
            bind_quote(socketFd, quote->signature, quote->signature_len);
        }

        return result;
    } while (false);

    return 0;
}