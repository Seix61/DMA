
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_ISSUER_NONCE_RESPONSE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_ISSUER_NONCE_RESPONSE_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class IssuerNonceResponseMessage : public MessageBase {
    private:
        IssuerNonce nonce;
    public:
        IssuerNonceResponseMessage() : MessageBase(IssuerNonceResponse), nonce({}) {}

        explicit IssuerNonceResponseMessage(const IssuerNonce &nonce) :
                MessageBase(IssuerNonceResponse), nonce(nonce) {}

        const IssuerNonce &getNonce() const {
            return nonce;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &nonce, sizeof(nonce));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &nonce, sizeof(nonce));
        }

        static size_t contentSize() {
            return sizeof(nonce);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_ISSUER_NONCE_RESPONSE_H
