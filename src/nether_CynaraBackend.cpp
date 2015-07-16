#include "nether_CynaraBackend.h"

// #ifdef HAVE_CYNARA

NetherCynaraBackend::NetherCynaraBackend(const NetherConfig &netherConfig)
    :   NetherPolicyBackend(netherConfig), currentCynaraDescriptor(0),
        cynaraLastResult(CYNARA_API_UNKNOWN_ERROR)
{
    responseQueue.reserve(1024);
}

NetherCynaraBackend::~NetherCynaraBackend()
{
}

const bool NetherCynaraBackend::initialize()
{
    cynaraLastResult  = cynara_async_initialize(&cynaraContext, NULL, &statusCallback, this);
    if (cynaraLastResult != CYNARA_API_SUCCESS)
    {
        LOGE("Failed to initialize cynara client " << cynaraErrorCodeToString(cynaraLastResult));
        return (false);
    }

    return (true);
}

void NetherCynaraBackend::statusCallback(int oldFd, int newFd, cynara_async_status status, void *data)
{
    LOGD("oldFd=" << oldFd << "newFd=" << newFd);

    NetherCynaraBackend *backend = static_cast<NetherCynaraBackend *>(data);

    if (status == CYNARA_STATUS_FOR_READ)
        backend->setCynaraDescriptor(newFd, readOnly);

    if (status == CYNARA_STATUS_FOR_RW)
        backend->setCynaraDescriptor(newFd, readWrite);
}

void NetherCynaraBackend::checkCallback(cynara_check_id check_id,
                                        cynara_async_call_cause cause,
                                        int response,
                                        void *data)
{
    NetherCynaraBackend *backend = static_cast<NetherCynaraBackend *>(data);

    if (cause == CYNARA_CALL_CAUSE_ANSWER)
        backend->setCynaraVerdict (check_id, response);
    else
        LOGI("unknown reason for call cause="<< cause <<" response="<< response);
}

const bool NetherCynaraBackend::enqueueVerdict (const NetherPacket &packet)
{
    char user[NETHER_MAX_USER_LEN];
    cynara_check_id checkId;

    snprintf (user, sizeof(user), "%du", packet.uid);

    cynaraLastResult = cynara_async_check_cache(cynaraContext, packet.securityContext.c_str(), "", user, NETHER_CYNARA_INTERNET_PRIVILEGE);

    switch (cynaraLastResult)
    {
        case CYNARA_API_ACCESS_ALLOWED:
            LOGD(cynaraErrorCodeToString(cynaraLastResult).c_str());
            return (castVerdict(packet, allow));

        case CYNARA_API_ACCESS_DENIED:
            LOGD(cynaraErrorCodeToString(cynaraLastResult).c_str());
            return (castVerdict(packet, deny));

        case CYNARA_API_CACHE_MISS:
            cynaraLastResult = cynara_async_create_request(cynaraContext,
                                                packet.securityContext.c_str(),
                                                "",
                                                user,
                                                NETHER_CYNARA_INTERNET_PRIVILEGE,
                                                &checkId,
                                                &checkCallback,
                                                this);
            if (cynaraLastResult == CYNARA_API_SUCCESS)
            {
                responseQueue.insert (responseQueue.begin() + checkId, packet.id);

                return (true);
            }
            else if (cynaraLastResult == CYNARA_API_SERVICE_NOT_AVAILABLE)
            {
                LOGW("Cynara offline, fall back to another backend");
                return (false);
            }
            else
            {
                LOGW("Error on cynara request create after CYNARA_API_CACHE_MISS " << cynaraErrorCodeToString(cynaraLastResult));
                return (false);
            }

        default:
            LOGW("Error on cynara request create unhandled result from cynara_async_check_cache "<<cynaraErrorCodeToString(cynaraLastResult));
            return (false);
    }

    return (true);
}

void NetherCynaraBackend::setCynaraVerdict(cynara_check_id checkId, int cynaraResult)
{
    u_int32_t packetId = 0;
    if ((packetId = responseQueue.at(checkId)) >= 0)
    {
        responseQueue.erase(responseQueue.begin() + checkId);

        if (cynaraResult == CYNARA_API_ACCESS_ALLOWED)
            castVerdict (packetId, allow);
        else
            castVerdict (packetId, deny);

        return;
    }

    LOGW("checkId=" << checkId << " has no assosiated packetId");
}

const bool NetherCynaraBackend::isValid()
{
    return ((cynaraLastResult ==  CYNARA_API_SUCCESS ? true : false) && cynaraContext);
}

const int NetherCynaraBackend::getDescriptor()
{
    return (currentCynaraDescriptor);
}

const NetherDescriptorStatus NetherCynaraBackend::getDescriptorStatus()
{
    return (currentCynaraDescriptorStatus);
}

void NetherCynaraBackend::setCynaraDescriptor(const int _currentCynaraDescriptor, const NetherDescriptorStatus _currentCynaraDescriptorStatus)
{
    currentCynaraDescriptorStatus   = _currentCynaraDescriptorStatus;
    currentCynaraDescriptor         = _currentCynaraDescriptor;
}

const bool NetherCynaraBackend::processEvents()
{
    int ret = cynara_async_process(cynaraContext);

    if (ret == CYNARA_API_SUCCESS)
        return (true);

    LOGW("cynara_async_process failed " << cynaraErrorCodeToString(ret));
    return (false);
}
//#endif
