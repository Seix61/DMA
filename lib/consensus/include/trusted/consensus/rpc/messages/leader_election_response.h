
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_LEADER_ELECTION_RESPONSE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_LEADER_ELECTION_RESPONSE_H

#include <cstdint>
#include <consensus/rpc/message_base.h>

namespace Consensus {
    class LeaderElectionResponseMessage : public MessageBase {
    private:
        int term;
    public:
        LeaderElectionResponseMessage() : MessageBase(LeaderElectionResponse), term(-1) {}

        explicit LeaderElectionResponseMessage(int term) : MessageBase(LeaderElectionResponse), term(term) {}

        int getTerm() const {
            return term;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &term, sizeof(term));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &term, sizeof(term));
        }

        static size_t contentSize() {
            return sizeof(term);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_LEADER_ELECTION_RESPONSE_H
