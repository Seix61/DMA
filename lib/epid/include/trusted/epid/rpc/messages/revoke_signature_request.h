
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_REVOKE_SIGNATURE_REQUEST_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_REVOKE_SIGNATURE_REQUEST_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class RevokeSignatureRequestMessage : public MessageBase {
    private:
        size_t size;
        EpidNonSplitSignature signature;
    public:
        RevokeSignatureRequestMessage() : MessageBase(RevokeSignatureRequest), size(0), signature({}) {}

        explicit RevokeSignatureRequestMessage(size_t size, const EpidNonSplitSignature &signature) :
                MessageBase(RevokeSignatureRequest), size(size), signature(signature) {}

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

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_REVOKE_SIGNATURE_REQUEST_H
