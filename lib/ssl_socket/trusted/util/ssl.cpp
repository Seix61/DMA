
#include <util/ssl.h>
#include <util/log.h>
#include <util/memory.h>

const char *SSLUtil::DefaultSubjectName = "CN=Intel SGX Enclave,O=Intel Corporation,C=US";
const char *SSLUtil::DefaultDateNotValidBefore = "20210401000000";
const char *SSLUtil::DefaultDateNotValidAfter = "20501231235959";

sgx_status_t SSLUtil::defaultCertInit(const std::shared_ptr<SSLKey> &key, std::shared_ptr<SSLX509> &cert) {
    cert = std::make_shared<SSLX509>();
    do {
        if (cert->create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create X.509.");
#endif
            break;
        }
        if (cert->setKeyPair(key->getPKey()) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 key pair.");
#endif
            break;
        }
        if (cert->setVersion(2) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 version.");
#endif
            break;
        }
        if (cert->setSubjectName((const unsigned char *) SSLUtil::DefaultSubjectName) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 subject name.");
#endif
            break;
        }
        if (cert->setIssuerName((const unsigned char *) SSLUtil::DefaultSubjectName) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 issuer name.");
#endif
            break;
        }
        if (cert->setSerialNumber(1) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 serial number.");
#endif
            break;
        }
        if (cert->setNotBefore((const unsigned char *) SSLUtil::DefaultDateNotValidBefore) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 not before.");
#endif
            break;
        }
        if (cert->setNotAfter((const unsigned char *) SSLUtil::DefaultDateNotValidAfter) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set X.509 not after.");
#endif
            break;
        }
        if (cert->prepareExtension() != SGX_SUCCESS) {
            break;
        }
        if (cert->addExtension(NID_basic_constraints, "CA:FALSE") != SGX_SUCCESS) {
            break;
        }
        if (cert->addExtension(NID_subject_key_identifier, "hash") != SGX_SUCCESS) {
            break;
        }
        if (cert->addExtension(NID_authority_key_identifier, "keyid:always") != SGX_SUCCESS) {
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLUtil::getServerRandom(const SSL *session, std::shared_ptr<unsigned char> &out, size_t &size) {
    if ((out = Memory::makeShared<unsigned char>(SSL3_RANDOM_SIZE)) == nullptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    size = SSL3_RANDOM_SIZE;
    SSL_get_server_random(session, out.get(), SSL3_RANDOM_SIZE);
    return SGX_SUCCESS;
}

sgx_status_t SSLUtil::getClientRandom(const SSL *session, std::shared_ptr<unsigned char> &out, size_t &size) {
    if ((out = Memory::makeShared<unsigned char>(SSL3_RANDOM_SIZE)) == nullptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    size = SSL3_RANDOM_SIZE;
    SSL_get_client_random(session, out.get(), SSL3_RANDOM_SIZE);
    return SGX_SUCCESS;
}
