
#include <epid/role/member.h>
#include <ippmath/memory.h>
#include <epid/util/random.h>
#include <epid/util/gen_f.h>
#include <epid/util/rl_size.h>
#include <util/log.h>

EPIDMember::EPIDMember(const GroupPubKey &pub_key) : pubKey(pub_key) {
    this->params.rnd_func = epid_random_func;
    this->params.rnd_param = nullptr;
    this->params.max_precomp_sig = 1;
    this->params.max_sigrl_entries = 10;
    this->params.f = (FpElemStr *) malloc(sizeof(FpElemStr));
    if (this->params.f == nullptr) {
        LOG_ERROR("Failed to malloc FpElemStr.");
    }
}

EPIDMember::~EPIDMember() {
    delete this->params.f;
    delete this->sigRl;
    if (this->ctx) {
        EpidMemberDeinit(this->ctx);
        free(this->ctx);
    }
}

sgx_status_t EPIDMember::create() {
    EpidStatus ret = kEpidErr;
    do {
        if ((ret = (EpidStatus) sgx_gen_epid_priv_f((void *) this->params.f)) != kEpidNoErr) {
            LOG_ERROR("Failed to sgx_gen_epid_priv_f.");
            break;
        }

        size_t member_size;
        if ((ret = EpidMemberGetSize(&this->params, &member_size)) != kEpidNoErr) {
            LOG_ERROR("Failed to EpidMemberGetSize.");
            break;
        }

        this->ctx = (MemberCtx *) malloc(member_size);
        if (this->ctx == nullptr) {
            LOG_ERROR("Failed to malloc MemberCtx.");
            return SGX_ERROR_OUT_OF_MEMORY;
        }

        if ((ret = EpidMemberInit(&this->params, this->ctx)) != kEpidNoErr) {
            LOG_ERROR("Failed to EpidMemberInit.");
            break;
        }

        if ((ret = EpidMemberSetHashAlg(this->ctx, kSha256)) != kEpidNoErr) {
            LOG_ERROR("Failed to EpidMemberSetHashAlg.");
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return (sgx_status_t) ret;
}

sgx_status_t EPIDMember::createJoinRequest(const IssuerNonce &nonce, NoneSplitJoinRequest &join_req) {
    return (sgx_status_t) EpidCreateJoinRequest(this->ctx, &this->pubKey, &nonce, &join_req, sizeof(NoneSplitJoinRequest));
}

sgx_status_t EPIDMember::provision(const MembershipCredential &member_cred) {
    return (sgx_status_t) EpidProvisionCredential(this->ctx, &this->pubKey, &member_cred, nullptr);
}

sgx_status_t EPIDMember::setSigRl(SigRl *rl) {
    uint32_t rl_size = EpidGetSigRlSize(rl);
//    delete this->sigRl;
    if ((this->sigRl = (SigRl *) malloc(rl_size)) == nullptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    memcpy(this->sigRl, rl, rl_size);
    return (sgx_status_t) EpidMemberSetSigRl(this->ctx, this->sigRl, rl_size);
}

sgx_status_t EPIDMember::startUp() {
    return (sgx_status_t) EpidMemberStartup(this->ctx);
}

sgx_status_t EPIDMember::getSigSize(size_t &size) {
    size = EpidGetSigSize(this->sigRl);
    return SGX_SUCCESS;
}

sgx_status_t EPIDMember::sign(const void *msg, size_t msg_len, const void *basename, size_t basename_len,
                              EpidNonSplitSignature &signature, size_t signature_len) {
    return (sgx_status_t) EpidSign(this->ctx, msg, msg_len, basename, basename_len, &signature, signature_len);
}

sgx_status_t EPIDMember::exportPrivF(FpElemStr &f) const {
    memcpy(&f, this->params.f, sizeof(FpElemStr));
    return SGX_SUCCESS;
}
