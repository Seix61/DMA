
#ifndef LIB_UTIL_IAS_VERIFY_H
#define LIB_UTIL_IAS_VERIFY_H

#include <sgx_quote.h>
#include <memory>
#include <vector>

class IasVerify {
private:
    static std::vector<std::string> quoteStatus;
public:
    static bool verifyAttestationVerificationReport(const std::string &verification_report,
                                                    const std::string &signature,
                                                    const std::string &signing_certificate,
                                                    bool &result);

    static void parseQuoteFromVerificationReport(const std::string &verification_report,
                                                 std::shared_ptr<sgx_quote_t> &quote, size_t &quote_size);

    static void parseNonceFromVerificationReport(const std::string &verification_report,
                                                 std::string &nonce);

    static void parseQuoteStatusFromVerificationReport(const std::string &verification_report,
                                                       uint32_t &status);
};

#endif //LIB_UTIL_IAS_VERIFY_H
