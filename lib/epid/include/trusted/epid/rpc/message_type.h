
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_TYPE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_TYPE_H

namespace Epid {
    enum MessageType {
        Default,
        AttStatusRequest,
        AttStatusResponse,
        IssuerNonceRequest,
        IssuerNonceResponse,
        GroupKeyRequest,
        GroupKeyResponse,
        MemberJoinRequest,
        MemberJoinResponse,
        RevokeMemberBySigRequest,
        RevokeSignatureRequest,
        PrivRLRequest,
        PrivRLResponse,
        SigRLRequest,
        SigRLResponse,
        SignatureRLRequest,
        SignatureRLResponse,
        RLRequest,
        RLResponse,
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_TYPE_H
