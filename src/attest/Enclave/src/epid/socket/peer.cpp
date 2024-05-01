
#include "Enclave_t.h"
#include "epid/socket/peer.h"

#include <memory>
#include <sgx_error.h>
#include <sgx_tcrypto.h>
#include <ssl_socket/define.h>
#include <util/ssl.h>
#include <util/sgx/attestation_helper.h>
#include <util/codec/base64.h>
#include <util/log.h>
#include <util/memory.h>

extern bool ignoreOriginalTrust;
extern GeneralSettings::AttestationType originalAttestationType;

int EpidPeer::setCert(SSL *session, void *arg, const unsigned char *peer_nonce, size_t peer_nonce_size,
                      const unsigned char *self_nonce, size_t self_nonce_size) {
    auto key = (std::shared_ptr<SSLKey> *) arg;

    do {
        std::shared_ptr<SSLX509> x509;
        SSLUtil::defaultCertInit(*key, x509);

        if (!ignoreOriginalTrust) {
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
            if (sgx_sha256_update((uint8_t *) peer_nonce, peer_nonce_size, sha_handle) != SGX_SUCCESS) {
                LOG_ERROR("Failed to sgx_sha256_update.");
                break;
            }
            if (sgx_sha256_update((uint8_t *) self_nonce, self_nonce_size, sha_handle) != SGX_SUCCESS) {
                LOG_ERROR("Failed to sgx_sha256_update.");
                break;
            }
            if (sgx_sha256_update((uint8_t *) pub, pub_size, sha_handle) != SGX_SUCCESS) {
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
            std::shared_ptr<sgx_quote_t> quote;
            size_t quoteSize;
            SgxAttestationHelper::getSelfQuote(originalAttestationType, userData, sizeof(sgx_sha256_hash_t), quote, quoteSize);
            if (quote == nullptr) {
                LOG_ERROR("Failed to get self quote.");
                break;
            }
            if (x509->addCostumeExtension(OID_FOR_QUOTE_STRING, (uint8_t *) quote.get(), quoteSize) != SGX_SUCCESS) {
                LOG_ERROR("Failed to add extension into cert.");
                break;
            }
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

int EpidPeer::verifyCert(X509 *&cert, const unsigned char *self_nonce, size_t self_nonce_size,
                         const unsigned char *peer_nonce, size_t peer_nonce_size, int socketFd) {
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

        if (ignoreOriginalTrust) {
            return 1;
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

        size_t quote_size = 0;
        std::shared_ptr<uint8_t> quote_buffer;
        if (x509->getCostumeExtension(OID_FOR_QUOTE_STRING, quote_buffer, quote_size) != SGX_SUCCESS) {
            LOG_ERROR("Failed to get costume extension from certificate.");
            break;
        }
        auto quote = Memory::copyOf<uint8_t, sgx_quote_t>(quote_buffer, quote_size);
#ifdef LOG_VERBOSE
        LOG_DEBUG("\n[%d] %s", quote_size, Codec::Base64::encode((char *)quote.get(), quote_size).c_str());
        LOG_INFO("Extension buffer read = %s", SgxDump::sgxQuoteToString(quote.get()).c_str());
#endif

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

        auto report_data = quote->report_body.report_data;
#ifdef LOG_VERBOSE
        LOG_INFO("Verifying UserData = %s, Recalculate = %s", Codec::Base64::encode((const char *) &report_data).c_str(), Codec::Base64::encode((const char *) &userData).c_str());
#endif
        if (memcmp(&report_data, &userData, sizeof(sgx_sha256_hash_t)) != 0) {
            LOG_ERROR("UserData not match.");
            break;
        }

        bool result = false;
        uint32_t quoteStatus = -1;
        SgxAttestationHelper::verifyQuote(originalAttestationType, quote, quote_size, result, quoteStatus);
        LOG_INFO("Verify Attestation Verification Report = %d", result);
        if (!result) {
            break;
        }

        std::shared_ptr<sgx_report_t> selfReport;
        SgxAttestationHelper::createSelfReport(nullptr, 0, selfReport);
        if (memcmp(&selfReport->body.mr_signer, &quote->report_body.mr_signer, sizeof(sgx_measurement_t)) != 0) {
            break;
        }

        return 1;
    } while (false);

    return 0;
}