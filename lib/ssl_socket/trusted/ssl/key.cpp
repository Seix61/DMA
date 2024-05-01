
#include <ssl_socket/ssl/key.h>
#include <cstring>
#include <util/log.h>

SSLKey::SSLKey() : pKey(EVP_PKEY_new()) {}

SSLKey::~SSLKey() {
    if (this->pKey) {
        EVP_PKEY_free(this->pKey);
    }
}

EVP_PKEY *SSLKey::getPKey() const {
    return this->pKey;
}

sgx_status_t SSLKey::generateByRSA() {
    int res;
    RSA *rsa = nullptr;
    BIGNUM *e = nullptr;

    do {
        if (!(e = BN_new())) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BN_new.");
#endif
            break;
        }
        if (!(res = BN_set_word(e, (BN_ULONG) RSA_F4))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BN_set_word. Returned %d.", res);
#endif
            break;
        }
        if (!(rsa = RSA_new())) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to RSA_new.");
#endif
            break;
        }
        if (!(res = RSA_generate_key_ex(
                rsa,
                3072,   /* number of bits for the key value */
                e,      /* exponent - RSA_F4 is defined as 0x10001L */
                nullptr /* callback argument - not needed in this case */
        ))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to RSA_generate_key. Returned %d.", res);
#endif
            break;
        }
        // Assign RSA key to EVP_PKEY structure
        EVP_PKEY_assign_RSA(this->pKey, rsa);

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLKey::generateByEC() {
    int res;
    EVP_PKEY_CTX *ctx = nullptr;

    do {
        if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to EVP_PKEY_CTX_new_id.");
#endif
            break;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to EVP_PKEY_keygen_init.");
#endif
            break;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to EVP_PKEY_CTX_set_ec_paramgen_curve_nid.");
#endif
            break;
        }
        if (EVP_PKEY_keygen(ctx, &this->pKey) <= 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to EVP_PKEY_keygen.");
#endif
            break;
        }

        EVP_PKEY_CTX_free(ctx);
        return SGX_SUCCESS;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLKey::generate() {
    return this->generateByEC();
}

sgx_status_t SSLKey::getPublicKeyInPEM(uint8_t *&key, size_t *size) {
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    int res;
    BIO *bio = nullptr;
    long key_size;

    do {
        if (key != nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Key must be nullptr before get.");
#endif
            result = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        if (!(bio = BIO_new(BIO_s_mem()))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BIO_new.");
#endif
            break;
        }
        if (!(res = PEM_write_bio_PUBKEY(bio, this->pKey))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to PEM_write_bio_PUBKEY. Returned %d.", res);
#endif
            break;
        }
        if ((key_size = BIO_pending(bio)) <= 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to get size of PEM data.");
#endif
            break;
        }
        if (!(key = (uint8_t *) malloc(key_size))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to allocate key. Out of memory.");
#endif
            result = SGX_ERROR_OUT_OF_EPC;
            break;
        }
        memset(key, 0x00, key_size);
        if (!(res = BIO_read(bio, key, key_size))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BIO_read. Returned %d.", res);
#endif
            break;
        }
        *size = strlen(reinterpret_cast<const char *>(key)) + 1;

        result = SGX_SUCCESS;
    } while (false);

    if (bio) {
        BIO_free(bio);
    }

    return result;
}

sgx_status_t SSLKey::getPrivateKeyInPEM(uint8_t *&key, size_t *size) {
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    int res;
    BIO *bio = nullptr;
    long key_size;

    do {
        if (key != nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Key must be nullptr before get.");
#endif
            result = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        if (!(bio = BIO_new(BIO_s_mem()))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BIO_new.");
#endif
            break;
        }
        if (!(res = PEM_write_bio_PrivateKey(bio, this->pKey, nullptr, nullptr, 0, nullptr, nullptr))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to PEM_write_bio_PrivateKey. Returned %d.", res);
#endif
            break;
        }
        if ((key_size = BIO_pending(bio)) <= 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to get size of PEM data.");
#endif
            break;
        }
        if (!(key = (uint8_t *) malloc(key_size))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to allocate key. Out of memory.");
#endif
            result = SGX_ERROR_OUT_OF_EPC;
            break;
        }
        memset(key, 0x00, key_size);
        if (!(res = BIO_read(bio, key, key_size))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BIO_read. Returned %d.", res);
#endif
            break;
        }
        *size = strlen(reinterpret_cast<const char *>(key)) + 1;

        result = SGX_SUCCESS;
    } while (false);

    if (bio) {
        BIO_free(bio);
    }

    return result;
}
