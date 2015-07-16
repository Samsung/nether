#ifndef NETHER_POLICY_BACKEND_H
#define NETHER_POLICY_BACKEND_H

#include "nether_Types.h"
#include "nether_Utils.h"

class NetherPolicyBackend : public NetherVerdictCaster
{
    public:
        NetherPolicyBackend(const NetherConfig &_netherConfig) : netherConfig(_netherConfig) {}
        virtual ~NetherPolicyBackend() {}
        virtual const bool enqueueVerdict (const NetherPacket &packet) = 0;
        virtual const bool initialize() = 0;
        virtual const bool reload() { return (true); };
        virtual const bool isValid() = 0;
        virtual const int getDescriptor() { return (-1); }
        virtual const NetherDescriptorStatus getDescriptorStatus() { return (unknownStatus); }
        virtual const bool processEvents() = 0;

    protected:
        NetherConfig netherConfig;
};

#endif
