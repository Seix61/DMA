
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_RECOVER_RESPONSE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_RECOVER_RESPONSE_H

#include <cstdint>
#include <map>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class RecoverResponseMessage : public MessageBase {
    private:
        size_t count;
        std::map<int, int> idIndex;
    public:
        RecoverResponseMessage() : MessageBase(RecoverResponse), count(0), idIndex() {}

        explicit RecoverResponseMessage(const std::map<int, int> &idIndex)
                : MessageBase(RecoverResponse), count(idIndex.size()), idIndex(idIndex) {}

        size_t getCount() const {
            return count;
        }

        const std::map<int, int> &getIdIndex() const {
            return idIndex;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &count, sizeof(count));
            for (const auto &pair : idIndex) {
                oss.write((char *)&pair.first, sizeof(int));
                oss.write((char *)&pair.second, sizeof(int));
            }
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &count, sizeof(count));
            for (int i = 0; i < count; i++) {
                int id = 0, index = 0;
                iss.read((char *)&id, sizeof(int));
                iss.read((char *)&index, sizeof(int));
                idIndex[id] = index;
            }
        }

        static size_t staticSize() {
            return sizeof(count);
        }

        static size_t contentSize() {
            return sizeof(count);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_RECOVER_RESPONSE_H
