
#include <ssl_socket/ssl/x509.h>
#include <mbusafecrt.h>
#include <openssl/x509.h>
#include <util/log.h>
#include <util/memory.h>
#include <openssl/pem.h>

SSLX509::SSLX509() {
    OPENSSL_init_crypto(0, nullptr);
}

SSLX509::~SSLX509() {
    if (this->cert) {
        X509_free(this->cert);
    }
}

X509 *SSLX509::getCert() const {
    return this->cert;
}

X509_NAME *SSLX509::parseName(const char *name_string) {
    const char *s = name_string;
    const char *c = s;
    const char *end = s + strlen(s);
    int in_tag = 1;
    char key[X509_MAX_NAME_SIZE];
    char data[X509_MAX_NAME_SIZE];
    char *d = data;
    X509_NAME *name = NULL;
    int error = 1;

    name = X509_NAME_new();
    if (name == NULL)
        goto done;

    while (c <= end) {
        if (in_tag && *c == '=') {
            size_t len = (size_t) (c - s) + 1;
            if (len > X509_MAX_NAME_SIZE)
                goto done;

            if (memcpy_s(key, X509_MAX_NAME_SIZE, s, len))
                goto done;
            key[len - 1] = '\0';
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end) {
            c++;
            /* Only support escaping commas */
            if (c == end || *c != ',')
                goto done;
        } else if (!in_tag && (*c == ',' || c == end)) {
            /*
             * The check of if(d - data == OE_X509_MAX_NAME_SIZE)
             * below ensures that d should never go beyond the boundary of data.
             * Place null that indicates the end of the string.
             */
            *d = '\0';
            if (!X509_NAME_add_entry_by_txt(
                    name, key, MBSTRING_UTF8, (unsigned char *) data, -1, -1, 0))
                goto done;

            /* Skip the spaces after the comma */
            while (c < end && *(c + 1) == ' ')
                c++;
            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1) {
            *(d++) = *c;
            if (d - data == X509_MAX_NAME_SIZE)
                goto done;
        }

        c++;
    }

    error = 0;

    done:
    if (error && name) {
        X509_NAME_free(name);
        name = NULL;
    }

    return name;
}

char *SSLX509::formatDateString(const char *date_string) {
    char *ret = new char[16];
    strncpy(ret, (const char *) date_string, 14);
    ret[14] = 'Z';
    ret[15] = '\0';
    return ret;
}

sgx_status_t SSLX509::create() {
    if ((this->cert = X509_new()) == nullptr) {
        return SGX_ERROR_OUT_OF_EPC;
    }
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::setVersion(int version) {
    if (!X509_set_version(this->cert, version)) {
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::setKeyPair(EVP_PKEY *_pkey) {
    EVP_PKEY *_tmp_pkey;
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, _pkey);
    _tmp_pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!X509_set_pubkey(this->cert, _tmp_pkey)) {
        return SGX_ERROR_UNEXPECTED;
    }
    this->pkey = _pkey;
    BIO_free(bio);
    EVP_PKEY_free(_tmp_pkey);
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::setSubjectName(const unsigned char *name_string) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    X509_NAME *name = nullptr;

    do {
        if (!(name = this->parseName((const char *) name_string))) {
            break;
        }
        if (!X509_set_subject_name(this->cert, name)) {
            break;
        }
        ret = SGX_SUCCESS;
    } while (false);

    X509_NAME_free(name);
    return ret;
}

sgx_status_t SSLX509::setIssuerName(const unsigned char *name_string) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    X509_NAME *name = nullptr;

    do {
        if (!(name = this->parseName((const char *) name_string))) {
            break;
        }
        if (!X509_set_issuer_name(this->cert, name)) {
            break;
        }
        ret = SGX_SUCCESS;
    } while (false);

    X509_NAME_free(name);
    return ret;
}

sgx_status_t SSLX509::setSerialNumber(int sn) {
    if (!ASN1_INTEGER_set(X509_get_serialNumber(this->cert), sn)) {
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::setNotBefore(const unsigned char *date_string) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    char *date;
    do {
        if (!(date = this->formatDateString((const char *) date_string))) {
            break;
        }
        if (!ASN1_TIME_set_string(X509_getm_notBefore(this->cert), date)) {
            break;
        }
        ret = SGX_SUCCESS;
    } while (false);

    if (date) {
        free(date);
    }
    return ret;
}

sgx_status_t SSLX509::setNotAfter(const unsigned char *date_string) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    char *date;
    do {
        if (!(date = this->formatDateString((const char *) date_string))) {
            break;
        }
        if (!ASN1_TIME_set_string(X509_getm_notAfter(this->cert), date)) {
            break;
        }
        ret = SGX_SUCCESS;
    } while (false);

    if (date) {
        free(date);
    }
    return ret;
}

sgx_status_t SSLX509::prepareExtension() {
    /* No configuration database */
    X509V3_set_ctx_nodb(&this->ctx);
    /* Use the target as both issuer and subject for the self-signed certificate. */
    X509V3_set_ctx(&this->ctx, this->cert, this->cert, nullptr, nullptr, 0);
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::addExtension(int nid, const char *value) {
    sgx_status_t ret;
    X509_EXTENSION *ext = nullptr;
    do {
        if (!(ext = X509V3_EXT_conf_nid(nullptr, &this->ctx, nid, value))) {
            ret = SGX_ERROR_OUT_OF_EPC;
            break;
        }
        if (!X509_add_ext(this->cert, ext, -1)) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        ret = SGX_SUCCESS;
    } while (false);

    if (ext) {
        X509_EXTENSION_free(ext);
    }
    return ret;
}

sgx_status_t SSLX509::addCostumeExtension(const char *oid, const uint8_t *buffer, size_t size) {
    sgx_status_t ret;
    ASN1_OCTET_STRING *data = nullptr;
    ASN1_OBJECT *obj = nullptr;
    X509_EXTENSION *ext = nullptr;

    do {
        if (!(data = ASN1_OCTET_STRING_new())) {
            ret = SGX_ERROR_OUT_OF_EPC;
            break;
        }
        if (!ASN1_OCTET_STRING_set(data, (const unsigned char *) buffer, (int) size)) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if (!(obj = OBJ_txt2obj(oid, 1))) {
            ret = SGX_ERROR_OUT_OF_EPC;
            break;
        }
        if (!X509_EXTENSION_create_by_OBJ(&ext, obj, 0, data)) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        if (!X509_add_ext(this->cert, ext, -1)) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        ret = SGX_SUCCESS;
    } while (false);


    if (data) {
        ASN1_OCTET_STRING_free(data);
    }
    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    if (ext) {
        X509_EXTENSION_free(ext);
    }
    return ret;
}

sgx_status_t SSLX509::sign() {
    if (!X509_sign(this->cert, this->pkey, EVP_sha256())) {
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::getCertInPEM(uint8_t *&crt, size_t *size) {
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    int res;
    BIO *bio = nullptr;
    long crt_size;

    do {
        if (crt != nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Crt must be nullptr before get.");
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
        if (!(res = PEM_write_bio_X509(bio, this->cert))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to PEM_write_bio_X509. Returned %d.", res);
#endif
            break;
        }
        if ((crt_size = BIO_pending(bio)) <= 0)  {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to get size of PEM data.");
#endif
            break;
        }
        if (!(crt = (uint8_t *) malloc(crt_size))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to allocate cert. Out of memory.");
#endif
            result = SGX_ERROR_OUT_OF_EPC;
            break;
        }
        memset(crt, 0x00, crt_size);
        if (!(res = BIO_read(bio, crt, crt_size))) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to BIO_read. Returned %d.", res);
#endif
            break;
        }
        *size = strlen(reinterpret_cast<const char *>(crt)) + 1;

        result = SGX_SUCCESS;
    } while (false);

    if (bio) {
        BIO_free(bio);
    }

    return result;
}

sgx_status_t SSLX509::load(X509 *cert) {
    if (this->cert != nullptr) {
        return SGX_ERROR_UNEXPECTED;
    }
    this->cert = cert;
    return SGX_SUCCESS;
}

sgx_status_t SSLX509::getPublicKeyInPEM(uint8_t *&key, size_t *size) {
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
        if (!(res = PEM_write_bio_PUBKEY(bio, X509_get0_pubkey(this->cert)))) {
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

sgx_status_t SSLX509::verify(bool &result) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    X509_STORE_CTX *storeCtx = nullptr;
    X509_STORE *store = nullptr;

    do {
        if (!(store = X509_STORE_new())) {
            break;
        }
        /* Create a context for verification */
        if (!(storeCtx = X509_STORE_CTX_new())) {
            break;
        }
        /* Initialize the context that will be used to verify the certificate */
        if (!X509_STORE_CTX_init(storeCtx, store, nullptr, nullptr)) {
            break;
        }
        /* Inject the certificate into the verification context */
        X509_STORE_CTX_set_cert(storeCtx, this->cert);
        /* Set the CA chain into the verification context */
        X509_STORE_add_cert(store, this->cert);
        /* Finally verify the certificate */
        if (!X509_verify_cert(storeCtx)) {
            if ((X509_STORE_CTX_get_error(storeCtx)) != X509_V_OK) {
                result = false;
                break;
            } else {
                result = true;
            }
        } else {
            result = true;
        }

        ret = SGX_SUCCESS;
    } while (false);

    if (store) {
        X509_STORE_free(store);
    }
    if (storeCtx) {
        X509_STORE_CTX_free(storeCtx);
    }

    return ret;
}

sgx_status_t SSLX509::getCostumeExtension(const char *oid, std::shared_ptr<uint8_t> &buffer, size_t &size) {
    const STACK_OF(X509_EXTENSION) *extensions;
    if (!(extensions = X509_get0_extensions(this->cert))) {
        return SGX_ERROR_UNEXPECTED;
    }

    int extensionCount = sk_X509_EXTENSION_num(extensions);
    for (int i = 0; i < extensionCount; i++) {
        X509_EXTENSION *ext;
        ASN1_OBJECT *obj;
        char current_oid[256];

        /* Get the i-th extension from the stack */
        if (!(ext = sk_X509_EXTENSION_value(extensions, i))) {
            return SGX_ERROR_UNEXPECTED;
        }
        /* Get the OID */
        if (!(obj = X509_EXTENSION_get_object(ext))) {
            return SGX_ERROR_UNEXPECTED;
        }
        /* Get the string name of the OID */
        if (!OBJ_obj2txt(current_oid, sizeof(current_oid), obj, 1)) {
            return SGX_ERROR_UNEXPECTED;
        }
        /* If found then get the data */
        if (strcmp(current_oid, oid) == 0) {
            ASN1_OCTET_STRING *str;

            /* Get the data from the extension */
            if (!(str = X509_EXTENSION_get_data(ext))) {
                return SGX_ERROR_UNEXPECTED;
            }
            /* If the caller's buffer is too small, raise error */
            if ((buffer = Memory::makeShared<uint8_t>(str->length)) == nullptr) {
                return SGX_ERROR_OUT_OF_MEMORY;
            }
            if (buffer) {
                size = str->length;
                memcpy(buffer.get(), str->data, (size_t) str->length);
                return SGX_SUCCESS;
            }
        }
    }

    return SGX_ERROR_UNEXPECTED;
}
