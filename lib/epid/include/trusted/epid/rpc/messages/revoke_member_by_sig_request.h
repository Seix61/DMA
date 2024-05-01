
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_REVOKE_MEMBER_BY_SIG_REQUEST_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_REVOKE_MEMBER_BY_SIG_REQUEST_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class RevokeMemberBySigRequestMessage : public MessageBase {
    private:
        size_t size;
        EpidNonSplitSignature signature;
    public:
        RevokeMemberBySigRequestMessage() : MessageBase(RevokeMemberBySigRequest), size(0), signature({}) {}

        explicit RevokeMemberBySigRequestMessage(size_t size, const EpidNonSplitSignature &signature) :
                MessageBase(RevokeMemberBySigRequest), size(size), signature(signature) {}

        size_t getSize() const {
            return size;
        }

        const EpidNonSplitSignature &getSignature() const {
            return signature;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &size, sizeof(size));
            oss.write((char *) &signature, size);
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &size, sizeof(size));
            iss.read((char *) &signature, size);
        }

        static size_t staticSize() {
            return sizeof(size);
        }

        static size_t contentSize() {
            return sizeof(size);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_REVOKE_MEMBER_BY_SIG_REQUEST_H
