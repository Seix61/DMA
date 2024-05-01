
#ifndef LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_QUOTE_REQUEST_H
#define LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_QUOTE_REQUEST_H

#include <attestation/rpc/message_base.h>
#include <sgx_report.h>

namespace Attestation {
    class QuoteRequestMessage : public MessageBase {
    private:
        sgx_report_t report;
    public:
        QuoteRequestMessage() : MessageBase(QuoteRequest), report({}) {}

        explicit QuoteRequestMessage(const sgx_report_t &report) :
                MessageBase(QuoteRequest), report(report) {}

        const sgx_report_t &getReport() const {
            return report;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &report, sizeof(report));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &report, sizeof(report));
        }

        static size_t contentSize() {
            return sizeof(report);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_QUOTE_REQUEST_H
