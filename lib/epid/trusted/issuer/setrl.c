
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>
#include <ippmath/memory.h>
#include <common/endian_convert.h>
#include <common/sigrlvalid.h>
#include <epid/util/rl_valid.h>

EpidStatus EpidIssuerSetPrivRl(IssuerCtx *ctx, const PrivRl *priv_rl, size_t priv_rl_size) {
    if (!ctx) {
        return kEpidBadCtxErr;
    }
    if (!ctx->pub_key) {
        return kEpidOutOfSequenceError;
    }
    if (!priv_rl || !IsPrivRlValid(&ctx->pub_key->gid, priv_rl, priv_rl_size)) {
        return kEpidBadPrivRlErr;
    }
    // Do not set an older version of priv rl
    if (ctx->priv_rl) {
        unsigned int current_ver = 0;
        unsigned int incoming_ver = 0;
        current_ver = ntohl(ctx->priv_rl->version);
        incoming_ver = ntohl(priv_rl->version);
        if (incoming_ver < current_ver) {
            return kEpidVersionMismatchErr;
        }
    }
    PrivRl *new_ptr = SAFE_REALLOC(ctx->priv_rl, priv_rl_size);
    if (!new_ptr) {
        return kEpidMemAllocErr;
    }
    if (memcpy_S(new_ptr, priv_rl_size, priv_rl, priv_rl_size) != 0) {
        return kEpidErr;
    }
    ctx->priv_rl = new_ptr;

    return kEpidNoErr;
}

EpidStatus EpidIssuerSetSigRl(IssuerCtx *ctx, const SigRl *sig_rl, size_t sig_rl_size) {
    if (!ctx) {
        return kEpidBadCtxErr;
    }
    if (!ctx->pub_key) {
        return kEpidOutOfSequenceError;
    }
    if (!sig_rl || !IsSigRlValid(&ctx->pub_key->gid, sig_rl, sig_rl_size)) {
        return kEpidBadSigRlErr;
    }
    // Do not set an older version of sig rl
    if (ctx->sig_rl) {
        unsigned int current_ver = 0;
        unsigned int incoming_ver = 0;
        current_ver = ntohl(ctx->sig_rl->version);
        incoming_ver = ntohl(sig_rl->version);
        if (incoming_ver < current_ver) {
            return kEpidVersionMismatchErr;
        }
    }
    SigRl *new_ptr = SAFE_REALLOC(ctx->sig_rl, sig_rl_size);
    if (!new_ptr) {
        return kEpidMemAllocErr;
    }
    if (memcpy_S(new_ptr, sig_rl_size, sig_rl, sig_rl_size) != 0) {
        return kEpidErr;
    }
    ctx->sig_rl = new_ptr;

    return kEpidNoErr;
}