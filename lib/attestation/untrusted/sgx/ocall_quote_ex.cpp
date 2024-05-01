
#include "attestation_u.h"

#include <sgx_uae_quote_ex.h>

sgx_status_t u_sgx_select_att_key_id(const uint8_t *p_att_key_id_list, uint32_t att_key_id_list_size,
                                     sgx_att_key_id_t *p_selected_key_id) {
    return sgx_select_att_key_id(p_att_key_id_list, att_key_id_list_size, p_selected_key_id);
}

sgx_status_t u_sgx_init_quote_ex(const sgx_att_key_id_t *p_att_key_id, sgx_target_info_t *p_qe_target_info,
                                 size_t *out_pub_key_id_size, uint8_t *p_pub_key_id, size_t in_pub_key_id_size) {
    if (in_pub_key_id_size > 0) {
        return sgx_init_quote_ex(p_att_key_id, p_qe_target_info, &in_pub_key_id_size, p_pub_key_id);
    }
    return sgx_init_quote_ex(p_att_key_id, p_qe_target_info, out_pub_key_id_size, p_pub_key_id);
}

sgx_status_t u_sgx_get_quote_size_ex(const sgx_att_key_id_t *p_att_key_id, uint32_t *p_quote_size) {
    return sgx_get_quote_size_ex(p_att_key_id, p_quote_size);
}

sgx_status_t u_sgx_get_quote_ex(const sgx_report_t *p_app_report, const sgx_att_key_id_t *p_att_key_id,
                                sgx_qe_report_info_t *p_qe_report_info, uint8_t *p_quote, uint32_t quote_size) {
    return sgx_get_quote_ex(p_app_report, p_att_key_id, p_qe_report_info, p_quote, quote_size);
}

sgx_status_t u_sgx_get_supported_att_key_id_num(uint32_t *p_att_key_id_num) {
    return sgx_get_supported_att_key_id_num(p_att_key_id_num);
}

sgx_status_t u_sgx_get_supported_att_key_ids(sgx_att_key_id_ext_t *p_att_key_id_list, uint32_t att_key_id_num) {
    return sgx_get_supported_att_key_ids(p_att_key_id_list, att_key_id_num);
}
