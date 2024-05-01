
#include "attestation_u.h"

#include <sgx_dcap_quoteverify.h>

quote3_error_t u_sgx_qv_get_quote_supplemental_data_size(uint32_t *p_supplemental_data_size) {
    return sgx_qv_get_quote_supplemental_data_size(p_supplemental_data_size);
}

quote3_error_t u_sgx_qv_verify_quote(const uint8_t *p_quote, uint32_t quote_size, time_t expiration_check_date,
                                     sgx_ql_qv_result_t *p_quote_verification_result,
                                     sgx_ql_qe_report_info_t *p_qve_report_info, size_t qve_report_info_size,
                                     uint8_t *p_supplemental_data, uint32_t supplemental_data_size) {
    uint32_t collateral_expiration_status = 1;

    if (p_quote == nullptr ||
        p_quote_verification_result == nullptr ||
        p_supplemental_data == nullptr ||
        (p_qve_report_info == nullptr && qve_report_info_size != 0) ||
        (p_qve_report_info != nullptr && qve_report_info_size <= 0))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    return sgx_qv_verify_quote(
            p_quote,
            quote_size,
            nullptr,
            expiration_check_date,
            &collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data);
}
