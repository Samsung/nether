#ifndef NETHER_NETLINK_H
#define NETHER_NETLINK_H

#include "nether_Types.h"
#include "nether_Utils.h"

class NetherManager;

class NetherNetlink : public NetherPacketProcessor
{
    public:
        NetherNetlink(NetherConfig &netherConfig);
        ~NetherNetlink();
        const bool initialize();
        const bool reload();
        static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
        const bool processPacket (char *packetBuffer, const int packetReadSize);
        void setVerdict(const u_int32_t packetId, const NetherVerdict verdict);
        int getDescriptor();
        const bool isValid();

    protected:
        NetherPacket *processedPacket;

    private:
        struct nfq_q_handle *queueHandle;
        struct nfq_handle *nfqHandle;
        struct nlif_handle *nlif;
        int fd;
        uint32_t queue;
};

#endif  // NETLINK_H_INCLUDED
