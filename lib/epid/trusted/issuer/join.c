
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>

typedef struct JoinPCommitValues {
    BigNumStr p;     ///< Intel(R) EPID 2.0 parameter p
    G1ElemStr g1;    ///< Intel(R) EPID 2.0 parameter g1
    G2ElemStr g2;    ///< Intel(R) EPID 2.0 parameter g2
    G1ElemStr h1;    ///< Group public key value h1
    G1ElemStr h2;    ///< Group public key value h2
    G2ElemStr w;     ///< Group public key value w
    G1ElemStr F;     ///< Variable F computed in algorithm
    G1ElemStr R;     ///< Variable R computed in algorithm
    IssuerNonce NI;  ///< Nonce
} JoinPCommitValues;

#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus
IsJoinRequestValid(GroupPubKey const *pub_key, IssuerNonce const *ni, HashAlg hash_alg, JoinRequest const *joinreq,
                   size_t joinreq_len, bool *is_valid) {
    EpidStatus result;
    BigNumStr cn_str;
    JoinPCommitValues commit_values;
    Epid2Params_ *params = NULL;
    FfElement *c_el = NULL;
    FfElement *cn_el = NULL;
    EcPoint *f_pt = NULL;
    EcPoint *r_pt = NULL;
    EcPoint *h1_pt = NULL;
    NoneSplitJoinRequest *request = NULL;

    if (!pub_key || !ni || !joinreq) {
        return kEpidBadArgErr;
    }
    if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg) {
        return kEpidBadArgErr;
    }
    if (joinreq_len >= sizeof(NoneSplitJoinRequest)) {
        request = (NoneSplitJoinRequest *) joinreq;
    } else {
        return kEpidNoMemErr;
    }

    do {
        result = CreateEpid2Params(&params);
        BREAK_ON_EPID_ERROR(result);
        if (!params->Fp || !params->G1) {
            result = kEpidBadArgErr;
            break;
        }
        result = NewFfElement(params->Fp, &c_el);
        BREAK_ON_EPID_ERROR(result);
        result = NewFfElement(params->Fp, &cn_el);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(params->G1, &f_pt);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(params->G1, &h1_pt);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(params->G1, &r_pt);
        BREAK_ON_EPID_ERROR(result);

        result = ReadEcPoint(params->G1, (uint8_t *) &request->F, sizeof(request->F), f_pt);
        BREAK_ON_EPID_ERROR(result);
        result = ReadEcPoint(params->G1, (uint8_t *) &pub_key->h1, sizeof(pub_key->h1), h1_pt);
        BREAK_ON_EPID_ERROR(result);
        result = ReadFfElement(params->Fp, (uint8_t *) &request->c, sizeof(request->c), c_el);
        BREAK_ON_EPID_ERROR(result);

        result = FfNeg(params->Fp, c_el, cn_el);
        BREAK_ON_EPID_ERROR(result);
        result = WriteFfElement(params->Fp, cn_el, (uint8_t *) &cn_str, sizeof(cn_str));
        BREAK_ON_EPID_ERROR(result);

        result = EcExp(params->G1, f_pt, (BigNumStr const *) &cn_str, f_pt);
        BREAK_ON_EPID_ERROR(result);

        result = EcExp(params->G1, h1_pt, (BigNumStr const *) &request->s, r_pt);
        BREAK_ON_EPID_ERROR(result);

        result = EcMul(params->G1, f_pt, r_pt, r_pt);
        BREAK_ON_EPID_ERROR(result);

        // Computes c = Fp.hash(p || g1 || g2 || h1 || h2 || w ||
        // F || R || NI). Refer to Section 7.1 for hash operation over a prime
        // field.
        result = WriteBigNum(params->p, sizeof(commit_values.p), (uint8_t *) &commit_values.p);
        BREAK_ON_EPID_ERROR(result);
        result = WriteEcPoint(params->G1, params->g1, (uint8_t *) &commit_values.g1, sizeof(commit_values.g1));
        BREAK_ON_EPID_ERROR(result);
        result = WriteEcPoint(params->G2, params->g2, (uint8_t *) &commit_values.g2, sizeof(commit_values.g2));
        BREAK_ON_EPID_ERROR(result);
        commit_values.h1 = pub_key->h1;
        commit_values.h2 = pub_key->h2;
        commit_values.w = pub_key->w;
        commit_values.F = request->F;
        result = WriteEcPoint(params->G1, r_pt, (uint8_t *) &commit_values.R, sizeof(commit_values.R));
        BREAK_ON_EPID_ERROR(result);
        commit_values.NI = *ni;
        result = FfHash(params->Fp, (uint8_t *) &commit_values, sizeof(commit_values), hash_alg, cn_el);
        BREAK_ON_EPID_ERROR(result);

        bool is_equal;
        result = FfIsEqual(params->Fp, cn_el, c_el, &is_equal);
        BREAK_ON_EPID_ERROR(result);
        *is_valid = is_equal;
        result = kEpidNoErr;
    } while (0);
    DeleteEcPoint(&h1_pt);
    DeleteEcPoint(&r_pt);
    DeleteEcPoint(&f_pt);
    DeleteFfElement(&cn_el);
    DeleteFfElement(&c_el);
    DeleteEpid2Params(&params);
    return result;
}

EpidStatus EpidCertifyMembership(IssuerCtx *ctx, JoinRequest const *joinreq, size_t joinreq_len, IssuerNonce const *ni,
                                 MembershipCredential *member_cred) {
    EpidStatus result = kEpidNoErr;
    NoneSplitJoinRequest *request = NULL;

    if (!joinreq || !ni || !ctx || !member_cred) {
        return kEpidBadArgErr;
    }
    if (joinreq_len >= sizeof(NoneSplitJoinRequest)) {
        request = (NoneSplitJoinRequest *) joinreq;
    } else {
        return kEpidNoMemErr;
    }

    EcGroup *G1 = ctx->epid2_params->G1;
    FiniteField *Fp = ctx->epid2_params->Fp;

    EcPoint *F_pt = NULL;
    EcPoint *A_pt = NULL;
    FfElement *x_el = NULL;

    do {
        GroupPubKey pub_key;
        EpidExportGroupPubKey(ctx, &pub_key);
        bool is_valid;
        result = IsJoinRequestValid(&pub_key, &ctx->ni, ctx->hash_alg, request, joinreq_len, &is_valid);
        BREAK_ON_EPID_ERROR(result);
        if (!is_valid) {
            result = kEpidNotImpl;
            break;
        }

        result = NewEcPoint(G1, &F_pt);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(G1, &A_pt);
        BREAK_ON_EPID_ERROR(result);
        result = NewFfElement(Fp, &x_el);
        BREAK_ON_EPID_ERROR(result);

        result = ReadEcPoint(G1, &request->F, sizeof(request->F), F_pt);
        BREAK_ON_EPID_ERROR(result);


        member_cred->gid = ctx->ipriv_key->gid;

        static const BigNumStr one = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
        result = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->rnd_param, x_el);
        BREAK_ON_EPID_ERROR(result);
        result = WriteFfElement(Fp, x_el, &member_cred->x, sizeof(member_cred->x));
        BREAK_ON_EPID_ERROR(result);

        result = FfAdd(Fp, x_el, ctx->ipriv_key->gamma, x_el);
        BREAK_ON_EPID_ERROR(result);
        result = FfInv(Fp, x_el, x_el);
        BREAK_ON_EPID_ERROR(result);

        BigNumStr x_str = {0};
        result = WriteFfElement(Fp, x_el, &x_str, sizeof(x_str));
        BREAK_ON_EPID_ERROR(result);

        result = EcMul(G1, F_pt, ctx->epid2_params->g1, A_pt);
        BREAK_ON_EPID_ERROR(result);
        result = EcExp(G1, A_pt, &x_str, A_pt);
        BREAK_ON_EPID_ERROR(result);
        result = WriteEcPoint(G1, A_pt, &member_cred->A, sizeof(member_cred->A));
        BREAK_ON_EPID_ERROR(result);

    } while (0);
    DeleteEcPoint(&F_pt);
    DeleteEcPoint(&A_pt);
    DeleteFfElement(&x_el);
    return result;
}