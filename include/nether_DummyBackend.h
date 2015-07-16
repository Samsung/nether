#ifndef NETHER_DUMMY_BACKEND_H
#define NETHER_DUMMY_BACKEND_H


#include "nether_PolicyBackend.h"

class NetherDummyBackend : public NetherPolicyBackend
{
    public:
        NetherDummyBackend(const NetherConfig &netherConfig)
            : NetherPolicyBackend(netherConfig) {}
        ~NetherDummyBackend() {}

        const bool isValid()
        {
            return (true);
        }

        const bool initialize()
        {
            return (true);
        }

        const bool enqueueVerdict(const NetherPacket &packet)
        {
            return (castVerdict (packet, netherConfig.defaultVerdict));
        }

        const bool processEvents()
        {
            return (true);
        }
};

#endif
