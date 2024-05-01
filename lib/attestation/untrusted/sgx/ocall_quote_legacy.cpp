
#include "attestation_u.h"

#include <sgx_uae_epid.h>

sgx_status_t u_sgx_init_quote(sgx_target_info_t *p_target_info, sgx_epid_group_id_t *p_gid) {
    return sgx_init_quote(p_target_info, p_gid);
}

sgx_status_t u_sgx_calc_quote_size(const uint8_t *p_sig_rl, uint32_t sig_rl_size, uint32_t *p_quote_size) {
    return sgx_calc_quote_size(p_sig_rl, sig_rl_size, p_quote_size);
}

sgx_status_t u_sgx_get_quote(const sgx_report_t *p_report, sgx_quote_sign_type_t quote_type, const sgx_spid_t *p_spid,
                             const sgx_quote_nonce_t *p_nonce, const uint8_t *p_sig_rl, uint32_t sig_rl_size,
                             sgx_report_t *p_qe_report, sgx_quote_t *p_quote, uint32_t quote_size) {
    return sgx_get_quote(p_report, quote_type, p_spid, p_nonce, p_sig_rl, sig_rl_size, p_qe_report, p_quote,
                         quote_size);
}
