
#ifndef LIB_TRUSTED_UTIL_SGX_ATTESTATION_HELPER_H
#define LIB_TRUSTED_UTIL_SGX_ATTESTATION_HELPER_H

#include <memory>
#include <sgx_error.h>
#include <sgx_report.h>
#include <sgx_quote.h>
#include <general_settings.h>

class SgxAttestationHelper {
private:
    static std::shared_ptr<uint8_t> getAttKeyIdListByEPID();

    static std::shared_ptr<uint8_t> getAttKeyIdListByDCAP();

    static sgx_status_t getSelfQuoteUsingLegacy(const void *data, size_t dataSize, std::shared_ptr<sgx_quote_t> &quote, size_t &quoteSize);

    static sgx_status_t getSelfQuoteUsingEx(GeneralSettings::AttestationType type, const void *data, size_t dataSize,
                                            std::shared_ptr<sgx_quote_t> &quote, size_t &quoteSize);

    static sgx_status_t verifyQuoteUsingIAS(const std::shared_ptr<sgx_quote_t> &quote, size_t quoteSize, bool &result,
                                            uint32_t &quoteStatus);

    static int verifyQuoteUsingQVL(const std::shared_ptr<sgx_quote_t> &quote, size_t quoteSize, bool &result,
                                   uint32_t &quoteStatus);

public:
    static sgx_status_t createSelfReport(const std::shared_ptr<sgx_target_info_t> &targetInfo, const void *data, size_t dataSize, std::shared_ptr<sgx_report_t> &report);

    static sgx_status_t createSelfReport(const sgx_target_info_t *targetInfo, const void *data, size_t dataSize, std::shared_ptr<sgx_report_t> &report);

    static sgx_status_t createSelfReport(const void *data, size_t dataSize, std::shared_ptr<sgx_report_t> &report);

    static sgx_status_t getSelfQuote(GeneralSettings::AttestationType type, const void *data, size_t dataSize,
                                     std::shared_ptr<sgx_quote_t> &quote, size_t &quoteSize);

    static int verifyQuote(GeneralSettings::AttestationType type, const std::shared_ptr<sgx_quote_t> &quote,
                           size_t quoteSize, bool &result, uint32_t &quoteStatus);
};

#endif //LIB_TRUSTED_UTIL_SGX_ATTESTATION_HELPER_H
