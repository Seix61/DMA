
#include <ssl_socket/ssl/context.h>
#include <util/log.h>

SSLContext::SSLContext(const SSL_METHOD *(*method)()) : method(method) {}

SSLContext::~SSLContext() {
    if (this->context) {
        SSL_CTX_free(this->context);
    }
    if (this->confContext) {
        SSL_CONF_CTX_free(this->confContext);
    }
}

SSL_CTX *SSLContext::getContext() const {
    return this->context;
}

sgx_status_t SSLContext::defaultInit() {
    const char *cipher_list_tlsv12_below =
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:"
            "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384";
    const char *cipher_list_tlsv13 = "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
    const char *supported_curves = "P-521:P-384:P-256";

    do {
        SSL_CONF_CTX_set_ssl_ctx(this->confContext, this->context);
        SSL_CONF_CTX_set_flags(this->confContext, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CLIENT);
        int ssl_conf_return_value = -1;
        if ((ssl_conf_return_value = SSL_CONF_cmd(this->confContext, "MinProtocol", "TLSv1.2")) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Setting MinProtocol for ssl context configuration failed with error %d.",
                      ssl_conf_return_value);
#endif
            break;
        }
        if ((ssl_conf_return_value = SSL_CONF_cmd(this->confContext, "MaxProtocol", "TLSv1.3")) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Setting MaxProtocol for ssl context configuration failed with error %d.",
                      ssl_conf_return_value);
#endif
            break;
        }
        if ((ssl_conf_return_value = SSL_CONF_cmd(this->confContext, "CipherString", cipher_list_tlsv12_below)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Setting CipherString for ssl context configuration failed with error %d.",
                      ssl_conf_return_value);
#endif
            break;
        }
        if ((ssl_conf_return_value = SSL_CONF_cmd(this->confContext, "CipherSuites", cipher_list_tlsv13)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Setting Ciphersuites for ssl context configuration failed with error %d.",
                      ssl_conf_return_value);
#endif
            break;
        }
        if ((ssl_conf_return_value = SSL_CONF_cmd(this->confContext, "Curves", supported_curves)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Setting Curves for ssl context configuration failed with error %d.", ssl_conf_return_value);
#endif
            break;
        }
        if (!SSL_CONF_CTX_finish(this->confContext)) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Error finishing ssl context configuration.");
#endif
            break;
        }
        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLContext::create() {
    do {
        if ((this->confContext = SSL_CONF_CTX_new()) == nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create a new SSL config context.");
#endif
            break;
        }
        if ((this->context = SSL_CTX_new(this->method())) == nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create a new SSL context.");
#endif
            break;
        }
        if (this->defaultInit() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to initialize SSL context.");
#endif
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLContext::setSetCertCallback(int (*callback)(SSL *, void *), void *arg) {
    SSL_CTX_set_cert_cb(this->context, callback, arg);
    return SGX_SUCCESS;
}
