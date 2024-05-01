
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_LEADER_ELECTION_REQUEST_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_LEADER_ELECTION_REQUEST_H

#include <cstdint>
#include <consensus/rpc/message_base.h>

namespace Consensus {
    class LeaderElectionRequestMessage : public MessageBase {
    private:
        int term;
    public:
        LeaderElectionRequestMessage() : MessageBase(LeaderElectionRequest), term(-1) {}

        explicit LeaderElectionRequestMessage(int term) : MessageBase(LeaderElectionRequest), term(term) {}

        int getTerm() const {
            return term;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *)&term, sizeof(term));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *)&term, sizeof(term));
        }

        static size_t contentSize() {
            return sizeof(term);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_LEADER_ELECTION_REQUEST_H
