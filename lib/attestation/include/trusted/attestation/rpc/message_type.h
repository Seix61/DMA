
#ifndef LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TYPE_H
#define LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TYPE_H

namespace Attestation {
    enum MessageType {
        Default,
        TargetInfoRequest,
        TargetInfoResponse,
        QuoteRequest,
        QuoteResponse,
        VerifyRequest,
        VerifyResponse,
        RevokeSigRequest,
    };
}

#endif //LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TYPE_H
