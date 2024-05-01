
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_GROUP_KEY_RESPONSE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_GROUP_KEY_RESPONSE_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class GroupKeyResponseMessage : public MessageBase {
    private:
        GroupPubKey pubKey;
    public:
        GroupKeyResponseMessage() : MessageBase(GroupKeyResponse), pubKey({}) {}

        explicit GroupKeyResponseMessage(const GroupPubKey &pubKey) :
                MessageBase(GroupKeyResponse), pubKey(pubKey) {}

        const GroupPubKey &getPubKey() const {
            return pubKey;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &pubKey, sizeof(pubKey));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &pubKey, sizeof(pubKey));
        }

        static size_t contentSize() {
            return sizeof(pubKey);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_GROUP_KEY_RESPONSE_H
