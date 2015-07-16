#ifndef NETHER_CYNARA_BACKEND_H
#define NETHER_CYNARA_BACKEND_H

// #ifdef HAVE_CYNARA

#include <cynara-client-async.h>
#include "nether_PolicyBackend.h"
#include <vector>

#define NETHER_CYNARA_INTERNET_PRIVILEGE "http://tizen.org/privilege/internet"

static const std::string cynaraErrorCodeToString(int cynaraErrorCode)
{
    char errorString[512];
    int ret;

    if ((ret = cynara_strerror(cynaraErrorCode, errorString, 512)) == CYNARA_API_SUCCESS)
        return (std::string(errorString, strlen(errorString)));
    else
        return ("Failed to get error string representation, code="+ret);
}

class NetherManager;

class NetherCynaraBackend : public NetherPolicyBackend
{
    public:
        NetherCynaraBackend(const NetherConfig &netherConfig);
        ~NetherCynaraBackend();
        const bool initialize();
        const bool isValid();
        const bool enqueueVerdict (const NetherPacket &packet);
        const bool processEvents();
        const int getDescriptor();
        const NetherDescriptorStatus getDescriptorStatus();
        void setCynaraDescriptor(const int _currentCynaraDescriptor, const NetherDescriptorStatus _currentCynaraDescriptorStatus);
        void setCynaraVerdict(cynara_check_id checkId, int cynaraResult);
        static void statusCallback(int oldFd, int newFd, cynara_async_status status, void *data);
        static void checkCallback(cynara_check_id check_id, cynara_async_call_cause cause, int response, void *data);

    private:
        cynara_async *cynaraContext;
        NetherDescriptorStatus currentCynaraDescriptorStatus;
        int currentCynaraDescriptor;
        std::vector<u_int32_t> responseQueue;
        int cynaraLastResult;
};

// #endif
#endif
