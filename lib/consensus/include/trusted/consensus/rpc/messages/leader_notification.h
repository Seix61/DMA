
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_FIRST_LEADER_NOTIFICATION_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_FIRST_LEADER_NOTIFICATION_H

#include <epid/issuer/api.h>
#include <consensus/rpc/message_base.h>

namespace Consensus {
    class LeaderNotificationMessage : public MessageBase {
    private:
        int term;
        GroupPubKey pubKey;
        IPrivKey privKey;
    public:
        LeaderNotificationMessage() : MessageBase(LeaderNotification), term(-1), pubKey({}), privKey({}) {}

        explicit LeaderNotificationMessage(int term, const GroupPubKey &pubKey, const IPrivKey &privKey) : MessageBase(
                LeaderNotification), term(term), pubKey(pubKey), privKey(privKey) {}

        int getTerm() const {
            return term;
        }

        const GroupPubKey &getPubKey() const {
            return pubKey;
        }

        const IPrivKey &getPrivKey() const {
            return privKey;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &term, sizeof(term));
            oss.write((char *) &pubKey, sizeof(pubKey));
            oss.write((char *) &privKey, sizeof(privKey));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &term, sizeof(term));
            iss.read((char *) &pubKey, sizeof(pubKey));
            iss.read((char *) &privKey, sizeof(privKey));
        }

        static size_t contentSize() {
            return sizeof(term) + sizeof(pubKey) + sizeof(privKey);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_FIRST_LEADER_NOTIFICATION_H
