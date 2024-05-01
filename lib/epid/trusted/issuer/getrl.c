
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>
#include <ippmath/memory.h>
#include <epid/util/rl_size.h>

size_t EpidIssuerGetPrivRlSize(const IssuerCtx *ctx) {
    if (!ctx) {
        return 0;
    }
    return EpidGetPrivRlSize(ctx->priv_rl);
}

EpidStatus EpidIssuerGetPrivRl(const IssuerCtx *ctx, PrivRl *priv_rl, size_t priv_rl_size) {
    if (!ctx) {
        return kEpidBadCtxErr;
    }
    size_t rl_size = EpidGetPrivRlSize(ctx->priv_rl);
    if (priv_rl_size < rl_size) {
        return kEpidBadArgErr;
    }
    if (memcpy_S(priv_rl, priv_rl_size, ctx->priv_rl, rl_size) != 0) {
        return kEpidErr;
    }
    return kEpidNoErr;
}

size_t EpidIssuerGetSigRlSize(const IssuerCtx *ctx) {
    if (!ctx) {
        return 0;
    }
    return EpidGetSigRlSize(ctx->sig_rl);
}

EpidStatus EpidIssuerGetSigRl(const IssuerCtx *ctx, SigRl *sig_rl, size_t sig_rl_size) {
    if (!ctx) {
        return kEpidBadCtxErr;
    }
    size_t rl_size = EpidGetSigRlSize(ctx->sig_rl);
    if (sig_rl_size < rl_size) {
        return kEpidBadArgErr;
    }
    if (memcpy_S(sig_rl, sig_rl_size, ctx->sig_rl, rl_size) != 0) {
        return kEpidErr;
    }
    return kEpidNoErr;
}
