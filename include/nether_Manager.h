#ifndef NETHER_MANAGER_H
#define NETHER_MANAGER_H

#include "nether_Types.h"
#include "nether_DummyBackend.h"
#include "nether_Netlink.h"


class NetherManager : public NetherVerdictListener, public NetherProcessedPacketListener
{
    public:
        NetherManager(const NetherConfig &_netherConfig);
        ~NetherManager();
        const bool initialize();
        const bool process();
        NetherConfig &getConfig();
        static NetherPolicyBackend *getPolicyBackend(const NetherConfig &netherConfig, const bool primary = true);
        bool verdictCast (const u_int32_t packetId, const NetherVerdict verdict);
        void packetReceived (const NetherPacket &packet);

    private:
        NetherPolicyBackend *netherPrimaryPolicyBackend, *netherBackupPolicyBackend;
        NetherDummyBackend *netherFallbackPolicyBackend;
        NetherNetlink *netherNetlink;
        NetherConfig netherConfig;
        int netlinkDescriptor, backendDescriptor, signalDescriptor;
        sigset_t signalMask;
};

#endif
