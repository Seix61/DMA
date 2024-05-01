
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_JOIN_REQUEST_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_JOIN_REQUEST_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class JoinRequestMessage : public MessageBase {
    private:
        NoneSplitJoinRequest request;
        IssuerNonce nonce;
    public:
        JoinRequestMessage() : MessageBase(MemberJoinRequest), request({}), nonce({}) {}

        explicit JoinRequestMessage(const NoneSplitJoinRequest &request, const IssuerNonce &nonce) :
                MessageBase(MemberJoinRequest), request(request), nonce(nonce) {}

        const NoneSplitJoinRequest &getRequest() const {
            return request;
        }

        const IssuerNonce &getNonce() const {
            return nonce;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &request, sizeof(request));
            oss.write((char *) &nonce, sizeof(nonce));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &request, sizeof(request));
            iss.read((char *) &nonce, sizeof(nonce));
        }

        static size_t contentSize() {
            return sizeof(request) + sizeof(nonce);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_JOIN_REQUEST_H
