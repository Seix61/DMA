
#include "attestation_t.h"

#include <util/ias_verify/ias_verify.h>
#include <util/log.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <util/codec/base64.h>
#include <util/memory.h>
#include <general_settings.h>

std::vector<std::string> IasVerify::quoteStatus = {};

bool IasVerify::verifyAttestationVerificationReport(const std::string &verification_report,
                                                    const std::string &signature,
                                                    const std::string &signing_certificate,
                                                    bool &result) {
    bool ret = false;
    BIO *pemBio = nullptr, *signatureBio = nullptr;
    X509 *x509 = nullptr;
    EVP_PKEY *pubkey = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;

    do {
        if (signing_certificate.find(GeneralSettings::IntelAttestationReportSigningCACert) == std::string::npos) {
            LOG_ERROR("Error verifying IAS certificate chain.");
            break;
        }
        if ((pemBio = BIO_new_mem_buf(signing_certificate.c_str(), -1)) == nullptr) {
            LOG_ERROR("Error creating BIO buffer for parsing X.509 certificate.");
            break;
        }
        if ((x509 = PEM_read_bio_X509(pemBio, nullptr, nullptr, nullptr)) == nullptr) {
            LOG_ERROR("Error loading X.509 certificate.");
            break;
        }
        if ((pubkey = X509_get_pubkey(x509)) == nullptr) {
            LOG_ERROR("Error extracting public key from X.509 certificate.");
            break;
        }
        if ((signatureBio = BIO_new_mem_buf(signature.c_str(), -1)) == nullptr) {
            LOG_ERROR("Error creating BIO buffer for parsing signature.");
            break;
        }
        std::string decodedSignature = Codec::Base64::decode(signature);
        // Verify the signature
        if ((md_ctx = EVP_MD_CTX_new()) == nullptr) {
            LOG_ERROR("Error creating EVP_MD CTX.");
            break;
        }
        EVP_MD_CTX_init(md_ctx);
        EVP_VerifyInit(md_ctx, EVP_sha256());
        EVP_VerifyUpdate(md_ctx, (const void *) verification_report.c_str(), verification_report.size());
        result = (EVP_VerifyFinal(md_ctx, (const unsigned char *) decodedSignature.c_str(), decodedSignature.size(),
                                  pubkey) == 1);

        ret = true;
    } while (false);

    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (signatureBio) {
        BIO_free_all(signatureBio);
    }
    if (pubkey) {
        EVP_PKEY_free(pubkey);
    }
    if (x509) {
        X509_free(x509);
    }
    if (pemBio) {
        BIO_free(pemBio);
    }

    return ret;
}

void IasVerify::parseQuoteFromVerificationReport(const std::string &verification_report,
                                                 std::shared_ptr<sgx_quote_t> &quote, size_t &quote_size) {
    sgx_status_t func_ret;
    if (u_ias_verify_parse_quote_size(&func_ret,
                                      verification_report.c_str(),
                                      verification_report.length(),
                                      &quote_size) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_verify_parse_quote_size.");
        return;
    }

    quote = Memory::makeShared<sgx_quote_t>(quote_size);
    if (u_ias_verify_parse_quote(&func_ret,
                                 verification_report.c_str(),
                                 verification_report.length(),
                                 quote.get(),
                                 quote_size) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_verify_parse_quote.");
        return;
    }
}

void IasVerify::parseNonceFromVerificationReport(const std::string &verification_report,
                                                 std::string &nonce) {
    sgx_status_t func_ret;
    size_t size;
    if (u_ias_verify_parse_nonce_size(&func_ret,
                                      verification_report.c_str(),
                                      verification_report.length(),
                                      &size) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_verify_parse_nonce_size.");
        return;
    }

    auto p_nonce = Memory::makeShared<char>(size);
    if (u_ias_verify_parse_nonce(&func_ret,
                                 verification_report.c_str(),
                                 verification_report.length(),
                                 p_nonce.get(),
                                 size) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_verify_parse_nonce.");
        return;
    }

    nonce = std::string(p_nonce.get(), size);
}

void IasVerify::parseQuoteStatusFromVerificationReport(const std::string &verification_report, uint32_t &status) {
    sgx_status_t func_ret;
    uint32_t tmp_status = -1;
    if (u_ias_verify_parse_quote_status(&func_ret,
                                       verification_report.c_str(),
                                       verification_report.length(),
                                       &tmp_status) != SGX_SUCCESS || func_ret != SGX_SUCCESS) {
        LOG_ERROR("Failed to u_ias_verify_parse_quote_status.");
        return;
    }
    status = tmp_status;
}
