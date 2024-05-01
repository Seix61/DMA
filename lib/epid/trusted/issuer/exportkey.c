
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>

#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidExportIssueKey(const IssuerCtx *ctx, IPrivKey *ext_ipriv_key) {
    EpidStatus result = kEpidErr;
    if (!ext_ipriv_key || !ctx) {
        return kEpidBadArgErr;
    }

    IPrivKey_ *ipriv_key = ctx->ipriv_key;
    FiniteField *Fp = ctx->epid2_params->Fp;

    do {
        result = WriteFfElement(Fp, ipriv_key->gamma, &ext_ipriv_key->gamma, sizeof(ext_ipriv_key->gamma));
        BREAK_ON_EPID_ERROR(result);
        ext_ipriv_key->gid = ipriv_key->gid;
        result = kEpidNoErr;
    } while (0);
    return result;
}

EpidStatus EpidExportGroupPubKey(const IssuerCtx *ctx, GroupPubKey *ext_pub_key) {
    EpidStatus result = kEpidErr;
    if (!ext_pub_key || !ctx) {
        return kEpidBadArgErr;
    }

    GroupPubKey_ *pubkey = ctx->pub_key;
    EcGroup *G1 = ctx->epid2_params->G1;
    EcGroup *G2 = ctx->epid2_params->G2;

    do {
        result = WriteEcPoint(G1, pubkey->h1, &ext_pub_key->h1, sizeof(ext_pub_key->h1));
        BREAK_ON_EPID_ERROR(result);
        result = WriteEcPoint(G1, pubkey->h2, &ext_pub_key->h2, sizeof(ext_pub_key->h2));
        BREAK_ON_EPID_ERROR(result);
        result = WriteEcPoint(G2, pubkey->w, &ext_pub_key->w, sizeof(ext_pub_key->w));
        BREAK_ON_EPID_ERROR(result);
        ext_pub_key->gid = pubkey->gid;
        result = kEpidNoErr;
    } while (0);
    return result;
}
