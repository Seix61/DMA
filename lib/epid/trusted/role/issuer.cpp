
#include <epid/role/issuer.h>
#include <epid/issuer/api.h>
#include <epid/util/random.h>
#include <util/memory.h>

EPIDIssuer::~EPIDIssuer() {
    if (this->ctx) {
        EpidIssuerDelete(&this->ctx);
    }
}

sgx_status_t EPIDIssuer::create() {
    return (sgx_status_t) EpidIssuerCreate(epid_random_func, nullptr, &this->ctx);
}

sgx_status_t EPIDIssuer::import(const GroupPubKey &pubKey, const IPrivKey &privKey) {
    return (sgx_status_t) EpidIssuerImport(&pubKey, &privKey, epid_random_func, nullptr, &this->ctx);
}

sgx_status_t EPIDIssuer::exportIssueKey(IPrivKey &key) {
    return (sgx_status_t) EpidExportIssueKey(this->ctx, &key);
}

sgx_status_t EPIDIssuer::exportGroupPubKey(GroupPubKey &key) {
    return (sgx_status_t) EpidExportGroupPubKey(this->ctx, &key);
}

sgx_status_t EPIDIssuer::getSigRlSize(size_t &size) {
    size = EpidIssuerGetSigRlSize(this->ctx);
    return SGX_SUCCESS;
}

sgx_status_t EPIDIssuer::getSigRl(SigRl *rl, size_t rl_size) {
    return (sgx_status_t) EpidIssuerGetSigRl(this->ctx, rl, rl_size);
}

sgx_status_t EPIDIssuer::getPrivRlSize(size_t &size) {
    size = EpidIssuerGetPrivRlSize(this->ctx);
    return SGX_SUCCESS;
}

sgx_status_t EPIDIssuer::setSigRl(const SigRl *rl, size_t rl_size) {
    return (sgx_status_t) EpidIssuerSetSigRl(this->ctx, rl, rl_size);
}

sgx_status_t EPIDIssuer::getPrivRl(PrivRl *rl, size_t rl_size) {
    return (sgx_status_t) EpidIssuerGetPrivRl(this->ctx, rl, rl_size);
}

sgx_status_t EPIDIssuer::setPrivRl(const PrivRl *rl, size_t rl_size) {
    return (sgx_status_t) EpidIssuerSetPrivRl(this->ctx, rl, rl_size);
}

sgx_status_t EPIDIssuer::generateNonce(IssuerNonce &ni) {
    return (sgx_status_t) EpidIssuerGenerateNonce(this->ctx, &ni);
}

sgx_status_t
EPIDIssuer::certifyMembership(const NoneSplitJoinRequest &join_req, const IssuerNonce &ni,
                              MembershipCredential &member_cred) {
    return (sgx_status_t) EpidCertifyMembership(this->ctx, &join_req, sizeof(NoneSplitJoinRequest), &ni, &member_cred);
}

sgx_status_t EPIDIssuer::revokeMemberByPriv(const FpElemStr &f) {
    return (sgx_status_t) EpidRevokePriv(this->ctx, &f);
}

sgx_status_t EPIDIssuer::revokeMemberBySig(const EpidNonSplitSignature &sig) {
    return (sgx_status_t) EpidRevokeSig(this->ctx, &sig);
}

sgx_status_t EPIDIssuer::getSignatureRl(std::shared_ptr<uint8_t> &rl, size_t &rl_size) {
    rl_size = this->signatureRl.serializedSize();
    rl = this->signatureRl.serialize();
    return SGX_SUCCESS;
}

sgx_status_t EPIDIssuer::setSignatureRl(const std::shared_ptr<uint8_t> &rl) {
    if (this->signatureRl.deserialize(rl)) {
        return SGX_SUCCESS;
    }
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t EPIDIssuer::revokeSignature(const EpidNonSplitSignature &sig, size_t size) {
    auto buffer = Memory::makeShared<uint8_t>((uint8_t *)&sig, size);
    if (this->signatureRl.push(buffer, size)) {
        return SGX_SUCCESS;
    }
    return SGX_ERROR_UNEXPECTED;
}
