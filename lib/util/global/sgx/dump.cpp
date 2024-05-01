
#include <util/sgx/dump.h>
#include <sstream>
#include <util/codec/base64.h>

std::string SgxDump::targetInfoToString(const sgx_target_info_t *target_into, const char *prefix) {
    std::stringstream ss;
    ss << prefix << "mr_enclave: "
       << Codec::Base64::encode(target_into->mr_enclave.m, sizeof(target_into->mr_enclave.m)) << std::endl;
    ss << prefix << "attributes: " << std::to_string(target_into->attributes.flags) << "|"
       << std::to_string(target_into->attributes.xfrm) << std::endl;
    ss << prefix << "config_svn: " << std::to_string(target_into->config_svn) << std::endl;
    ss << prefix << "misc_select: " << std::to_string(target_into->misc_select) << std::endl;
    ss << prefix << "config_id: " << Codec::Base64::encode(target_into->config_id, sizeof(target_into->config_id))
       << std::endl;
    return ss.str();
}

std::string SgxDump::sgxReportBodyToString(const sgx_report_body_t &body, const char *prefix) {
    std::stringstream ss;
    ss << prefix << "cpu_svn: " << Codec::Base64::encode(body.cpu_svn.svn, sizeof(body.cpu_svn.svn)) << std::endl;
    ss << prefix << "misc_select: " << std::to_string(body.misc_select) << std::endl;
    ss << prefix << "isv_ext_prod_id: " << Codec::Base64::encode(body.isv_ext_prod_id, sizeof(body.isv_ext_prod_id))
       << std::endl;
    ss << prefix << "attributes: " << std::to_string(body.attributes.flags) << "|"
       << std::to_string(body.attributes.xfrm) << std::endl;
    ss << prefix << "mr_enclave: " << Codec::Base64::encode(body.mr_enclave.m, sizeof(body.mr_enclave.m)) << std::endl;
    ss << prefix << "mr_signer: " << Codec::Base64::encode(body.mr_signer.m, sizeof(body.mr_signer.m)) << std::endl;
    ss << prefix << "config_id: " << Codec::Base64::encode(body.config_id, sizeof(body.config_id)) << std::endl;
    ss << prefix << "isv_prod_id: " << std::to_string(body.isv_prod_id) << std::endl;
    ss << prefix << "isv_svn: " << std::to_string(body.isv_svn) << std::endl;
    ss << prefix << "config_svn: " << std::to_string(body.config_svn) << std::endl;
    ss << prefix << "isv_family_id: " << Codec::Base64::encode(body.isv_family_id, sizeof(body.isv_family_id))
       << std::endl;
    ss << prefix << "report_data: " << Codec::Base64::encode(body.report_data.d, sizeof(body.report_data.d))
       << std::endl;
    return ss.str();
}

std::string SgxDump::sgxReportToString(const sgx_report_t *report, const char *prefix) {
    std::stringstream ss;
    ss << prefix << "key_id: " << Codec::Base64::encode(report->key_id.id, sizeof(report->key_id.id)) << std::endl;
    ss << prefix << "mac: " << Codec::Base64::encode(report->mac, sizeof(report->mac)) << std::endl;
    ss << prefix << "body: {" << std::endl;
    std::string indent = prefix;
    indent += indent;
    ss << SgxDump::sgxReportBodyToString(report->body, indent.c_str());
    ss << prefix << "}" << std::endl;
    return ss.str();
}

std::string SgxDump::sgxQuoteToString(const sgx_quote_t *quote, const char *prefix) {
    std::stringstream ss;
    ss << prefix << "version: " << std::to_string(quote->version) << std::endl;
    ss << prefix << "sign_type: " << std::to_string(quote->sign_type) << std::endl;
    ss << prefix << "epid_group_id: " << Codec::Base64::encode(quote->epid_group_id, sizeof(quote->epid_group_id))
       << std::endl;
    ss << prefix << "qe_svn: " << std::to_string(quote->qe_svn) << std::endl;
    ss << prefix << "pce_svn: " << std::to_string(quote->pce_svn) << std::endl;
    ss << prefix << "xeid: " << std::to_string(quote->xeid) << std::endl;
    ss << prefix << "basename: " << Codec::Base64::encode(quote->basename.name, sizeof(quote->basename.name))
       << std::endl;
    ss << prefix << "report_body: {" << std::endl;
    std::string indent = prefix;
    indent += indent;
    ss << SgxDump::sgxReportBodyToString(quote->report_body, indent.c_str());
    ss << prefix << "}" << std::endl;
    ss << prefix << "signature_len: " << std::to_string(quote->signature_len) << std::endl;
    ss << prefix << "signature: " << Codec::Base64::encode(quote->signature, quote->signature_len) << std::endl;
    return ss.str();
}

std::string SgxDump::targetInfoToString(const sgx_target_info_t *target_into) {
    std::stringstream ss;
    ss << std::endl;
    ss << "target_into: {" << std::endl;
    ss << SgxDump::targetInfoToString(target_into, "    ");
    ss << "}";
    return ss.str();
}

std::string SgxDump::sgxReportToString(const sgx_report_t *report) {
    std::stringstream ss;
    ss << std::endl;
    ss << "sgx_report: {" << std::endl;
    ss << SgxDump::sgxReportToString(report, "    ");
    ss << "}";
    return ss.str();
}

std::string SgxDump::sgxQuoteToString(const sgx_quote_t *quote) {
    std::stringstream ss;
    ss << std::endl;
    ss << "sgx_quote: {" << std::endl;
    ss << SgxDump::sgxQuoteToString(quote, "    ");
    ss << "}";
    return ss.str();
}

std::string SgxDump::sgxAttKeyIdToString(const sgx_att_key_id_ext_t *id, const char *prefix) {
    std::stringstream ss;
    ss << prefix << "base: {" << std::endl;
    std::string indent = prefix;
    indent += indent;
    ss << SgxDump::sgxQlAttKeyIdToString(&id->base, indent.c_str());
    ss << prefix << "}" << std::endl;
    ss << prefix << "spid: " << Codec::Base64::encode((char *)&id->spid, sizeof(id->spid)) << std::endl;
    ss << prefix << "att_key_type: " << std::to_string(id->att_key_type) << std::endl;
    ss << prefix << "reserved: " << Codec::Base64::encode((char *)&id->reserved, sizeof(id->reserved)) << std::endl;
    return ss.str();
}

std::string SgxDump::sgxQlAttKeyIdToString(const sgx_ql_att_key_id_t *id, const char *prefix) {
    std::stringstream ss;
    ss << prefix << "id: " << std::to_string(id->id) << std::endl;
    ss << prefix << "version: " << std::to_string(id->version) << std::endl;
    ss << prefix << "mrsigner_length: " << std::to_string(id->mrsigner_length) << std::endl;
    ss << prefix << "mrsigner: " << Codec::Base64::encode((char *)&id->mrsigner, sizeof(id->mrsigner)) << std::endl;
    ss << prefix << "prod_id: " << std::to_string(id->prod_id) << std::endl;
    ss << prefix << "extended_prod_id: " << Codec::Base64::encode((char *)&id->extended_prod_id, sizeof(id->extended_prod_id)) << std::endl;
    ss << prefix << "config_id: " << Codec::Base64::encode((char *)&id->config_id, sizeof(id->config_id)) << std::endl;
    ss << prefix << "family_id: " << Codec::Base64::encode((char *)&id->family_id, sizeof(id->family_id)) << std::endl;
    ss << prefix << "algorithm_id: " << std::to_string(id->algorithm_id) << std::endl;
    return ss.str();
}

std::string SgxDump::sgxAttKeyIdToString(const sgx_att_key_id_t *id) {
    return SgxDump::sgxAttKeyIdToString((sgx_att_key_id_ext_t *)id);
}

std::string SgxDump::sgxAttKeyIdToString(const sgx_att_key_id_ext_t *id) {
    std::stringstream ss;
    ss << std::endl;
    ss << "sgx_att_key_id: {" << std::endl;
    ss << SgxDump::sgxAttKeyIdToString(id, "    ");
    ss << "}";
    return ss.str();
}
