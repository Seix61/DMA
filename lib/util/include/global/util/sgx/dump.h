
#ifndef LIB_UTIL_SGX_DUMP_H
#define LIB_UTIL_SGX_DUMP_H

#include <sgx_report.h>
#include <sgx_quote.h>
#include <string>

class SgxDump {
private:
    static std::string targetInfoToString(const sgx_target_info_t *target_into, const char *prefix);

    static std::string sgxReportBodyToString(const sgx_report_body_t &body, const char *prefix);

    static std::string sgxReportToString(const sgx_report_t *report, const char *prefix);

    static std::string sgxQuoteToString(const sgx_quote_t *quote, const char *prefix);

    static std::string sgxQlAttKeyIdToString(const sgx_ql_att_key_id_t *id, const char *prefix);

    static std::string sgxAttKeyIdToString(const sgx_att_key_id_ext_t *id, const char *prefix);

public:
    static std::string targetInfoToString(const sgx_target_info_t *target_into);

    static std::string sgxReportToString(const sgx_report_t *report);

    static std::string sgxQuoteToString(const sgx_quote_t *quote);

    static std::string sgxAttKeyIdToString(const sgx_att_key_id_t *id);

    static std::string sgxAttKeyIdToString(const sgx_att_key_id_ext_t *id);
};

#endif //LIB_UTIL_SGX_DUMP_H
