
#include "attestation_u.h"

#include <string>
#include <cstring>
#include <sgx_error.h>
#include <sgx_quote.h>
#include <util/ias_verify/ias_verify.h>

sgx_status_t u_ias_verify_parse_quote_size(const char *p_verification_report, size_t verification_report_size,
                                           size_t *quote_size) {
    if (p_verification_report == nullptr || verification_report_size <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    size_t size;
    std::shared_ptr<sgx_quote_t> quote;
    IasVerify::parseQuoteFromVerificationReport(std::string(p_verification_report, verification_report_size), quote, size);

    memcpy(quote_size, &size, sizeof(size_t));

    return SGX_SUCCESS;
}

sgx_status_t u_ias_verify_parse_quote(const char *p_verification_report, size_t verification_report_size,
                                      sgx_quote_t *p_quote, size_t quote_size) {
    if (p_verification_report == nullptr || verification_report_size <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    size_t size;
    std::shared_ptr<sgx_quote_t> quote;
    IasVerify::parseQuoteFromVerificationReport(std::string(p_verification_report, verification_report_size), quote, size);

    if (quote_size < size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memcpy(p_quote, quote.get(), quote_size);

    return SGX_SUCCESS;
}

sgx_status_t u_ias_verify_parse_nonce_size(const char *p_verification_report, size_t verification_report_size,
                                           size_t *nonce_size) {
    if (p_verification_report == nullptr || verification_report_size <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::string nonce;
    IasVerify::parseNonceFromVerificationReport(std::string(p_verification_report, verification_report_size), nonce);

    auto length = nonce.length();
    memcpy(nonce_size, &length, sizeof(size_t));

    return SGX_SUCCESS;
}

sgx_status_t u_ias_verify_parse_nonce(const char *p_verification_report, size_t verification_report_size,
                                      char *p_quote, size_t nonce_size) {
    if (p_verification_report == nullptr || verification_report_size <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::string nonce;
    IasVerify::parseNonceFromVerificationReport(std::string(p_verification_report, verification_report_size), nonce);

    if (nonce_size < nonce.length()) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memcpy(p_quote, nonce.c_str(), nonce.length());

    return SGX_SUCCESS;
}

sgx_status_t u_ias_verify_parse_quote_status(const char *p_verification_report, size_t verification_report_size,
                                             uint32_t *p_status) {
    if (p_verification_report == nullptr || verification_report_size <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t status;
    IasVerify::parseQuoteStatusFromVerificationReport(std::string(p_verification_report, verification_report_size), status);

    *p_status = status;

    return SGX_SUCCESS;
}
