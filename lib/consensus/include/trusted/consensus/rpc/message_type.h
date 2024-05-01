
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_TYPE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_TYPE_H

namespace Consensus {
    enum MessageType {
        Default,
        LeaderElectionRequest,
        LeaderElectionResponse,
        LeaderNotification,
        AcceptRequest,
        AcceptResponse,
        CommitRequest,
        CommitResponse,
        TryAcceptRequest,
        TryAcceptResponse,
        TryCommitRequest,
        TryCommitResponse,
        RecoverRequest,
        RecoverResponse,
        PrepareRequest,
        PrepareResponse
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_TYPE_H
