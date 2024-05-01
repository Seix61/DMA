
#ifndef LIB_TRUSTED_EPID_ISSUER_API_H
#define LIB_TRUSTED_EPID_ISSUER_API_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>
#include <stddef.h>
#include <epid/errors.h>
#include <epid/types.h>
#include <epid/bitsupplier.h>

/// Internal context of issuer.
typedef struct IssuerCtx IssuerCtx;

/// definition of join request.
typedef void JoinRequest;

EpidStatus EpidIssuerCreate(BitSupplier rnd_func, void *rnd_param, IssuerCtx **ctx);

EpidStatus
EpidIssuerImport(const GroupPubKey *pub_key, const IPrivKey *ipriv_key, BitSupplier rnd_func, void *rnd_param,
                 IssuerCtx **ctx);

void EpidIssuerDelete(IssuerCtx **ctx);

EpidStatus EpidIssuerGenerateNonce(IssuerCtx *ctx, IssuerNonce *ni);

EpidStatus EpidCertifyMembership(IssuerCtx *ctx, const JoinRequest *joinreq, size_t joinreq_len, const IssuerNonce *ni,
                                 MembershipCredential *member_cred);

EpidStatus EpidExportGroupPubKey(const IssuerCtx *ctx, GroupPubKey *ext_pub_key);

EpidStatus EpidExportIssueKey(const IssuerCtx *ctx, IPrivKey *ext_ipriv_key);

size_t EpidIssuerGetPrivRlSize(const IssuerCtx *ctx);

EpidStatus EpidIssuerGetPrivRl(const IssuerCtx *ctx, PrivRl *priv_rl, size_t priv_rl_size);

EpidStatus EpidIssuerSetPrivRl(IssuerCtx *ctx, const PrivRl *priv_rl, size_t priv_rl_size);

size_t EpidIssuerGetSigRlSize(const IssuerCtx *ctx);

EpidStatus EpidIssuerGetSigRl(const IssuerCtx *ctx, SigRl *sig_rl, size_t sig_rl_size);

EpidStatus EpidIssuerSetSigRl(IssuerCtx *ctx, const SigRl *sig_rl, size_t sig_rl_size);

EpidStatus EpidRevokePriv(IssuerCtx *ctx, const FpElemStr *priv);

EpidStatus EpidRevokeSig(IssuerCtx *ctx, const EpidSignature *sig);

#ifdef __cplusplus
}
#endif

#endif //LIB_TRUSTED_EPID_ISSUER_API_H
