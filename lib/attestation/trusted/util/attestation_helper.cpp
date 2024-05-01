
#include "attestation_t.h"

#include <util/sgx/attestation_helper.h>
#include <sgx_utils.h>
#include <util/sgx/dump.h>
#include <util/codec/base64.h>
#include <util/memory.h>
#include <util/log.h>
#include <util/ias_verify/ias_verify.h>

std::shared_ptr<uint8_t> SgxAttestationHelper::getAttKeyIdListByEPID() {
    sgx_ql_att_key_id_list_header_t list_header{
            .id = 0,
            .version = 0,
            .num_att_ids = 1
    };
    sgx_att_key_id_ext_t att_id {
            .base = {
                    .id = 0,
                    .version = 0,
                    .mrsigner_length = 32,
                    .mrsigner = {
                            0xEC, 0x15, 0xB1, 0x07, 0x87, 0xD2, 0xF8, 0x46,
                            0x67, 0xCE, 0xB0, 0xB5, 0x98, 0xFF, 0xC4, 0x4A,
                            0x1F, 0x1C, 0xB8, 0x0F, 0x67, 0x0A, 0xAE, 0x5D,
                            0xF9, 0xE8,0xFA, 0x9F, 0x63, 0x76, 0xE1, 0xF8,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    },
                    .prod_id = 1,
                    .extended_prod_id = {0,},
                    .config_id = {0,},
                    .family_id = {0,},
                    .algorithm_id = 0,
            },
            .spid = {0},
            .att_key_type = 0,
            .reserved = {0,}
    };
    memcpy(&att_id.spid, &GeneralSettings::SPId.id, 16);
    auto list_size = sizeof(sgx_ql_att_key_id_list_header_t) + sizeof(sgx_att_key_id_ext_t);
    auto list = Memory::makeShared<uint8_t>(list_size);
    memcpy(list.get(), &list_header, sizeof(sgx_ql_att_key_id_list_header_t));
    memcpy(list.get() + sizeof(sgx_ql_att_key_id_list_header_t), &att_id, sizeof(sgx_att_key_id_ext_t));
    return list;
}

std::shared_ptr<uint8_t> SgxAttestationHelper::getAttKeyIdListByDCAP() {
    sgx_ql_att_key_id_list_header_t list_header{
            .id = 0,
            .version = 0,
            .num_att_ids = 1
    };
    sgx_att_key_id_ext_t att_id {
            .base = {
                    .id = 0,
                    .version = 0,
                    .mrsigner_length = 32,
                    .mrsigner = {
                            0x8C, 0x4F, 0x57, 0x75, 0xD7, 0x96, 0x50, 0x3E,
                            0x96, 0x13, 0x7F, 0x77, 0xC6, 0x8A, 0x82, 0x9A,
                            0x00, 0x56, 0xAC, 0x8D, 0xED, 0x70, 0x14, 0x0B,
                            0x08, 0x1B, 0x09, 0x44, 0x90, 0xC5, 0x7B, 0xFF,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    },
                    .prod_id = 1,
                    .extended_prod_id = {0,},
                    .config_id = {0,},
                    .family_id = {0,},
                    .algorithm_id = 2,
            },
            .spid = {0,},
            .att_key_type = 0,
            .reserved = {0,}
    };
    auto list_size = sizeof(sgx_ql_att_key_id_list_header_t) + sizeof(sgx_att_key_id_ext_t);
    auto list = Memory::makeShared<uint8_t>(list_size);
    memcpy(list.get(), &list_header, sizeof(sgx_ql_att_key_id_list_header_t));
    memcpy(list.get() + sizeof(sgx_ql_att_key_id_list_header_t), &att_id, sizeof(sgx_att_key_id_ext_t));
    return list;
}

sgx_status_t
SgxAttestationHelper::createSelfReport(const std::shared_ptr<sgx_target_info_t> &targetInfo, const void *data,
                                       size_t dataSize, std::shared_ptr<sgx_report_t> &report) {
    if (dataSize > 64) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t call_ret;

    sgx_report_data_t report_data{};
    memcpy(&report_data, data, dataSize);

    report = std::make_shared<sgx_report_t>();
    if ((call_ret = sgx_create_report(targetInfo.get(), &report_data, report.get())) != SGX_SUCCESS) {
        LOG_ERROR("Failed to sgx_create_report. Call returned 0x%X", call_ret);
        return call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("Self report = %s", SgxDump::sgxReportToString(report.get()).c_str());
#endif

    return SGX_SUCCESS;
}

sgx_status_t
SgxAttestationHelper::createSelfReport(const sgx_target_info_t *targetInfo, const void *data, size_t dataSize,
                                       std::shared_ptr<sgx_report_t> &report) {
    if (targetInfo == nullptr) {
        return createSelfReport(std::shared_ptr<sgx_target_info_t>(nullptr), data, dataSize, report);
    }
    return createSelfReport(std::make_shared<sgx_target_info_t>(*targetInfo), data, dataSize, report);
}

sgx_status_t
SgxAttestationHelper::createSelfReport(const void *data, size_t dataSize, std::shared_ptr<sgx_report_t> &report) {
    return createSelfReport(nullptr, data, dataSize, report);
}

sgx_status_t
SgxAttestationHelper::getSelfQuoteUsingLegacy(const void *data, size_t dataSize, std::shared_ptr<sgx_quote_t> &quote,
                                              size_t &quoteSize) {
    sgx_status_t call_ret, func_ret;

    sgx_target_info_t qe_target_info{};
    sgx_epid_group_id_t gid = {0};
    if ((call_ret = u_sgx_init_quote(&func_ret, &qe_target_info, &gid)) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_init_quote. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("QE's target_info = %s", SgxDump::targetInfoToString(&qe_target_info).c_str());
#endif

    std::shared_ptr<sgx_report_t> report;
    if ((call_ret = createSelfReport(&qe_target_info, data, dataSize, report)) != SGX_SUCCESS) {
        return call_ret;
    }

    uint32_t _quoteSize;
    if ((call_ret = u_sgx_calc_quote_size(&func_ret, nullptr, 0, &_quoteSize)) != SGX_SUCCESS ||
        func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_calc_quote_size. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
    quoteSize = _quoteSize;

    quote = Memory::makeShared<sgx_quote_t>(quoteSize);
    if ((call_ret = u_sgx_get_quote(&func_ret,
                                    report.get(),
                                    SGX_UNLINKABLE_SIGNATURE,
                                    &GeneralSettings::SPId,
                                    nullptr,
                                    nullptr, 0,
                                    nullptr,
                                    quote.get(), quoteSize)) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_get_quote. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("Self quote = %s", SgxDump::sgxQuoteToString(quote.get()).c_str());
#endif

    return SGX_SUCCESS;
}

sgx_status_t
SgxAttestationHelper::getSelfQuoteUsingEx(GeneralSettings::AttestationType type,
                                          const void *data, size_t dataSize,
                                          std::shared_ptr<sgx_quote_t> &quote, size_t &quoteSize) {
    sgx_status_t call_ret, func_ret;

    uint8_t att_key_id_list[264] = {0};
    if (type == GeneralSettings::EPID_BASED) {
        auto list = getAttKeyIdListByEPID();
        memcpy(&att_key_id_list, list.get(), 264);
    } else {
        auto list = getAttKeyIdListByDCAP();
        memcpy(&att_key_id_list, list.get(), 264);
    }

    sgx_att_key_id_t att_key_id;
    if ((call_ret = u_sgx_select_att_key_id(&func_ret, att_key_id_list, 264, &att_key_id)) != SGX_SUCCESS ||
        func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_select_att_key_id. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("key_id = %s", SgxDump::sgxAttKeyIdToString(&att_key_id).c_str());
#endif

    size_t pub_key_id_size = 0;
    sgx_target_info_t qe_target_info{};
    if ((call_ret = u_sgx_init_quote_ex(&func_ret, &att_key_id, &qe_target_info, &pub_key_id_size, nullptr, 0)) !=
        SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_init_quote_ex. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
    auto *pub_key_id = (uint8_t *) malloc(pub_key_id_size);
    if ((call_ret = u_sgx_init_quote_ex(&func_ret, &att_key_id, &qe_target_info, nullptr, pub_key_id,
                                        pub_key_id_size)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_init_quote_ex. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("pub_key_id = %s", Codec::Base64::encode(pub_key_id, pub_key_id_size).c_str());
#endif

    std::shared_ptr<sgx_report_t> report;
    if ((call_ret = createSelfReport(&qe_target_info, data, dataSize, report)) != SGX_SUCCESS) {
        return call_ret;
    }

    uint32_t _quoteSize = 0;
    if ((call_ret = u_sgx_get_quote_size_ex(&func_ret, &att_key_id, &_quoteSize)) != SGX_SUCCESS ||
        func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_get_quote_size_ex. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
    quoteSize = _quoteSize;

    sgx_qe_report_info_t p_qe_report_info;
    quote = Memory::makeShared<sgx_quote_t>(quoteSize);
    if ((call_ret = u_sgx_get_quote_ex(&func_ret, report.get(), &att_key_id, &p_qe_report_info, (uint8_t *) quote.get(),
                                       quoteSize)) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_get_quote_ex. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("Self quote = %s", SgxDump::sgxQuoteToString((sgx_quote_t *)quote.get()).c_str());
#endif

    return SGX_SUCCESS;
}

sgx_status_t
SgxAttestationHelper::getSelfQuote(GeneralSettings::AttestationType type,
                                   const void *data, size_t dataSize,
                                   std::shared_ptr<sgx_quote_t> &quote, size_t &quoteSize) {
    return getSelfQuoteUsingEx(type, data, dataSize, quote, quoteSize);
}

sgx_status_t
SgxAttestationHelper::verifyQuoteUsingIAS(const std::shared_ptr<sgx_quote_t> &quote, size_t quoteSize, bool &result,
                                          uint32_t &quoteStatus) {
    result = false;
    sgx_status_t call_ret, func_ret;

    uint8_t gid[4] = {0, 0, 0, 0};
    memcpy(&gid, &quote->epid_group_id, 4);

    size_t sig_rl_size = 0;
    uint64_t buffer_id = 0;
    if ((call_ret = u_ias_retrieve_sig_rl(&func_ret, gid, &sig_rl_size, &buffer_id)) != SGX_SUCCESS ||
        func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_retrieve_sig_rl. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
    if (sig_rl_size > 0 && buffer_id > 0) {
        auto sig_rl = Memory::makeShared<char>(sig_rl_size);
        if ((call_ret = u_ias_buffer_get(&func_ret, buffer_id, sig_rl.get(), sig_rl_size)) != SGX_SUCCESS ||
            func_ret != SGX_SUCCESS) {
            LOG_ERROR("Failed to u_ias_buffer_get. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
            return call_ret == SGX_SUCCESS ? func_ret : call_ret;
        }
#ifdef LOG_VERBOSE
        LOG_DEBUG("SigRL = %s", sig_rl.get());
#endif
    }

    auto nonce = Memory::makeShared<char>(16);
    if (quote) {
        memcpy(nonce.get(), &quote->report_body.report_data, 16);
    }

    size_t body_size = 0, signature_size = 0, certificate_size = 0;
    uint64_t body_buffer_id = 0, signature_buffer_id = 0, certificate_buffer_id = 0;
    if ((call_ret = u_ias_verify_attestation_evidence(&func_ret, quote.get(), quoteSize,
                                                      nonce.get(), 16,
                                                      &body_size, &body_buffer_id,
                                                      &signature_size, &signature_buffer_id,
                                                      &certificate_size, &certificate_buffer_id)) != SGX_SUCCESS ||
        func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_verify_attestation_evidence. Call returned 0x%X. Func returned 0x%X.", call_ret,
                  func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }

    std::string verification_report;
    std::string signature;
    std::string signing_certificate;
    if (body_size > 0 && body_buffer_id > 0) {
        auto temp = Memory::makeShared<char>(body_size);
        if ((call_ret = u_ias_buffer_get(&func_ret, body_buffer_id,
                                         temp.get(), body_size)) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
            LOG_ERROR("Failed to u_ias_buffer_get. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
            return call_ret == SGX_SUCCESS ? func_ret : call_ret;
        }
        verification_report = std::string(temp.get(), body_size);
    }
    if (signature_size > 0 && signature_buffer_id > 0) {
        auto temp = Memory::makeShared<char>(signature_size);
        if ((call_ret = u_ias_buffer_get(&func_ret, signature_buffer_id,
                                         temp.get(), signature_size)) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
            LOG_ERROR("Failed to u_ias_buffer_get. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
            return call_ret == SGX_SUCCESS ? func_ret : call_ret;
        }
        signature = std::string(temp.get(), signature_size);
    }
    if (certificate_size > 0 && certificate_buffer_id > 0) {
        auto temp = Memory::makeShared<char>(certificate_size);
        if ((call_ret = u_ias_buffer_get(&func_ret, certificate_buffer_id,
                                         temp.get(), certificate_size)) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
            LOG_ERROR("Failed to u_ias_buffer_get. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
            return call_ret == SGX_SUCCESS ? func_ret : call_ret;
        }
        signing_certificate = std::string(temp.get(), certificate_size);
    }

    if (!IasVerify::verifyAttestationVerificationReport(verification_report, signature, signing_certificate, result)) {
        LOG_ERROR("Failed to IasVerify::verifyAttestationVerificationReport.");
    }

    std::string report_nonce;
    IasVerify::parseNonceFromVerificationReport(verification_report, report_nonce);
    if (report_nonce.empty()) {
        LOG_ERROR("Failed to IasVerify::parseNonceFromVerificationReport.");
    }
    if (memcmp(report_nonce.c_str(), nonce.get(), 16) != 0) {
        LOG_ERROR("Nonce from verification_report not match.");
    }

    IasVerify::parseQuoteStatusFromVerificationReport(verification_report, quoteStatus);

    return SGX_SUCCESS;
}

int
SgxAttestationHelper::verifyQuoteUsingQVL(const std::shared_ptr<sgx_quote_t> &quote, size_t quoteSize, bool &result,
                                          uint32_t &quoteStatus) {
    result = false;

    sgx_status_t call_ret;
    quote3_error_t func_ret;
    uint32_t supplemental_data_size = 0;
    if ((call_ret = u_sgx_qv_get_quote_supplemental_data_size(&func_ret, &supplemental_data_size)) != SGX_SUCCESS ||
        func_ret != SGX_QL_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_get_supplemental_data_size_ocall. Call returned 0x%X. Func returned 0x%X.", call_ret,
                  func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }

    time_t expiration_check_time;
    if ((call_ret = u_current_time_secs(&expiration_check_time)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_current_time_secs. Call returned 0x%X", call_ret);
        return call_ret;
    }

    sgx_ql_qv_result_t qv_result;
    auto *supplemental_data = (uint8_t *) malloc(supplemental_data_size);
    if ((call_ret = u_sgx_qv_verify_quote(&func_ret,
                                          (uint8_t *) quote.get(), quoteSize,
                                          expiration_check_time,
                                          &qv_result,
                                          nullptr, 0,
                                          supplemental_data, supplemental_data_size)) != SGX_SUCCESS || func_ret != SGX_QL_SUCCESS) {
        LOG_ERROR("Failed to u_sgx_qv_verify_quote. Call returned 0x%X. Func returned 0x%X.", call_ret, func_ret);
        return call_ret == SGX_SUCCESS ? func_ret : call_ret;
    }
#ifdef LOG_VERBOSE
    LOG_DEBUG("qv_result = 0x%X", qv_result);
#endif

    result = true;
    quoteStatus = qv_result;
    free(supplemental_data);
    supplemental_data = nullptr;

    return SGX_SUCCESS;
}

int SgxAttestationHelper::verifyQuote(GeneralSettings::AttestationType type, const std::shared_ptr<sgx_quote_t> &quote,
                                      size_t quoteSize, bool &result, uint32_t &quoteStatus) {
    if (type == GeneralSettings::EPID_BASED) {
        return verifyQuoteUsingIAS(quote, quoteSize, result, quoteStatus);
    }
    return verifyQuoteUsingQVL(quote, quoteSize, result, quoteStatus);
}
