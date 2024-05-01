
#include "Enclave_t.h"
#include "node.h"

#include <util/ip.h>
#include <general_settings.h>

std::shared_ptr<AttestNode> attestNode;
bool ignoreOriginalTrust = false;
GeneralSettings::AttestationType originalAttestationType = GeneralSettings::EPID_BASED;

void ecall_launch_attest_node(int ignoreTrust, int useDCAP, int threadCount,
                              const char* epidServer, int epidConnect, int attestListen) {
    ignoreOriginalTrust = ignoreTrust == 1;
    originalAttestationType = useDCAP == 1 ? GeneralSettings::DCAP_BASED : GeneralSettings::EPID_BASED;

    attestNode = std::make_shared<AttestNode>(
            IPUtil::ipAddr2ULong(epidServer),
            epidConnect,
            attestListen,
            threadCount
    );
    attestNode->startEpidRole();
    attestNode->startAttestRole();
}
