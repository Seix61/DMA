
#ifndef LIB_TRUSTED_EPID_ROLE_ISSUER_H
#define LIB_TRUSTED_EPID_ROLE_ISSUER_H

#include <epid/issuer/api.h>
#include <sgx_error.h>
#include <epid/sig_rl.h>

class EPIDIssuer {
private:
    IssuerCtx *ctx = nullptr;
    SignatureRl signatureRl;
public:
    virtual ~EPIDIssuer();

    sgx_status_t create();

    sgx_status_t import(const GroupPubKey &pubKey, const IPrivKey &privKey);

    sgx_status_t exportIssueKey(IPrivKey &key);

    sgx_status_t exportGroupPubKey(GroupPubKey &key);

    sgx_status_t getSigRlSize(size_t &size);

    sgx_status_t getSigRl(SigRl *rl, size_t rl_size);

    sgx_status_t setSigRl(const SigRl *rl, size_t rl_size);

    sgx_status_t getPrivRlSize(size_t &size);

    sgx_status_t getPrivRl(PrivRl *rl, size_t rl_size);

    sgx_status_t setPrivRl(const PrivRl *rl, size_t rl_size);

    sgx_status_t generateNonce(IssuerNonce &ni);

    sgx_status_t
    certifyMembership(const NoneSplitJoinRequest &join_req, const IssuerNonce &ni, MembershipCredential &member_cred);

    sgx_status_t revokeMemberByPriv(const FpElemStr &f);

    sgx_status_t revokeMemberBySig(const EpidNonSplitSignature &sig);

    sgx_status_t getSignatureRl(std::shared_ptr<uint8_t> &rl, size_t &rl_size);

    sgx_status_t setSignatureRl(const std::shared_ptr<uint8_t> &rl);

    sgx_status_t revokeSignature(const EpidNonSplitSignature &sig, size_t size);
};

#endif //LIB_TRUSTED_EPID_ROLE_ISSUER_H
