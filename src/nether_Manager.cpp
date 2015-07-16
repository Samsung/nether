#include "nether_Manager.h"
#include "nether_CynaraBackend.h"
#include "nether_FileBackend.h"
#include "nether_DummyBackend.h"

NetherManager::NetherManager(const NetherConfig &_netherConfig)
    :   netherConfig(_netherConfig),
        netherPrimaryPolicyBackend(nullptr),
        netherBackupPolicyBackend(nullptr),
        netherFallbackPolicyBackend(nullptr)
{
    netherNetlink               = new NetherNetlink(netherConfig);
    netherNetlink->setListener (this);

    netherPrimaryPolicyBackend	= getPolicyBackend (netherConfig);
    netherPrimaryPolicyBackend->setListener (this);

    netherBackupPolicyBackend   = getPolicyBackend (netherConfig, false);
    netherBackupPolicyBackend->setListener (this);

    netherFallbackPolicyBackend = new NetherDummyBackend(netherConfig);
}

NetherManager::~NetherManager()
{
    deleteAndZero (netherPrimaryPolicyBackend);
    deleteAndZero (netherBackupPolicyBackend);
    deleteAndZero (netherFallbackPolicyBackend);
    deleteAndZero (netherNetlink);
    close (signalDescriptor);
}

const bool NetherManager::initialize()
{
    sigemptyset(&signalMask);
    sigaddset(&signalMask, SIGHUP);

    if (sigprocmask(SIG_BLOCK, &signalMask, NULL) == -1)
    {
        LOGE("Failed to block signals sigprocmask()");
        return (false);
    }

    signalDescriptor = signalfd(-1, &signalMask, 0);
    if (signalDescriptor == -1)
    {
        LOGE("Failed acquire signalfd descriptor");
        return (false);
    }

    if (!netherNetlink->initialize())
    {
        LOGE("Failed to initialize netlink subsystem, exiting");
        return (false);
    }

    if (!netherPrimaryPolicyBackend->initialize())
    {
        LOGE("Failed to initialize primary policy backend, exiting");
        return (false);
    }

    if (!netherBackupPolicyBackend->initialize())
    {
        LOGE("Failed to initialize backup backend, exiting");
        return (false);
    }

    if ((netlinkDescriptor = netherNetlink->getDescriptor()) == -1)
    {
        LOGE("Netlink subsystem did not return a valid descriptor, exiting");
        return (false);
    }

    if ((backendDescriptor = netherPrimaryPolicyBackend->getDescriptor()) == -1)
    {
        LOGI("Policy backend does not provide descriptor for select()");
    }
    return (true);
}

const bool NetherManager::process()
{
    NetherPacket receivedPacket;
    int packetReadSize;
    ssize_t signalRead;
    struct signalfd_siginfo signalfdSignalInfo;
    fd_set watchedReadDescriptorsSet, watchedWriteDescriptorsSet;
    struct timeval timeoutSpecification;
    char packetBuffer[NETHER_PACKET_BUFFER_SIZE] __attribute__ ((aligned));

    while (1)
    {
	    FD_ZERO (&watchedReadDescriptorsSet);
	    FD_ZERO (&watchedWriteDescriptorsSet);

        /* Always listen for signals */
        FD_SET (signalDescriptor, &watchedReadDescriptorsSet);

	    if ((netlinkDescriptor = netherNetlink->getDescriptor()) >= 0)
        {
            FD_SET(netlinkDescriptor, &watchedReadDescriptorsSet);
        }

        if ((backendDescriptor = netherPrimaryPolicyBackend->getDescriptor()) >= 0)
        {
            if (netherPrimaryPolicyBackend->getDescriptorStatus() == readOnly)
            {
                FD_SET(backendDescriptor, &watchedReadDescriptorsSet);
            }
            else if (netherPrimaryPolicyBackend->getDescriptorStatus() == readWrite)
            {
                FD_SET(backendDescriptor, &watchedReadDescriptorsSet);
                FD_SET(backendDescriptor, &watchedWriteDescriptorsSet);
            }
        }

	    timeoutSpecification.tv_sec     = 240;
        timeoutSpecification.tv_usec    = 0;

        if (select (FD_SETSIZE, &watchedReadDescriptorsSet, &watchedWriteDescriptorsSet, NULL, &timeoutSpecification) < 0)
        {
            LOGE("select error " << strerror(errno));
            return (false);
        }

        if (FD_ISSET(signalDescriptor, &watchedReadDescriptorsSet))
        {
            LOGD("received signal");
            signalRead = read (signalDescriptor, &signalfdSignalInfo, sizeof(struct signalfd_siginfo));

            if (signalRead != sizeof(struct signalfd_siginfo))
            {
                LOGW("Received incomplete signal information, ignore");
                continue;
            }

            if (signalfdSignalInfo.ssi_signo == SIGHUP)
            {
                LOGI("SIGHUP received, reloading");
                if (!netherPrimaryPolicyBackend->reload())
                    LOGW("primary backend failed to reload");
                if (!netherBackupPolicyBackend->reload())
                    LOGW("backup backend failed to reload");
                if (!netherNetlink->reload())
                    LOGW("netlink failed to reload");
                continue;
            }
        }
        if (FD_ISSET(netlinkDescriptor, &watchedReadDescriptorsSet))
        {
            LOGD("netlink descriptor active");

            /* some data arrives on netlink, read it */
            if ((packetReadSize = recv(netlinkDescriptor, packetBuffer, sizeof(packetBuffer), 0)) >= 0)
            {
                /* try to process the packet using netfilter_queue library, fetch packet info
                    needed for making a decision about it */
                if (netherNetlink->processPacket (packetBuffer, packetReadSize))
                {
                   continue;
                }
                else
                {
                    /* if we can't process the incoming packets, it's bad. Let's exit now */
                    LOGE("Failed to process netlink received packet, refusing to continue");
                    break;
                }
            }

            if (packetReadSize < 0 && errno == ENOBUFS)
            {
                LOGI("NetherManager::process losing packets! [bad things might happen]");
                continue;
            }

            LOGE("NetherManager::process recv failed " << strerror(errno));
            break;
        }
        else if (FD_ISSET(backendDescriptor, &watchedReadDescriptorsSet) || FD_ISSET(backendDescriptor, &watchedWriteDescriptorsSet))
        {
            LOGD("policy backend descriptor active");
            netherPrimaryPolicyBackend->processEvents();
        }
        else
        {
            LOGD("select() timeout");
        }
    }
}

NetherConfig &NetherManager::getConfig()
{
    return (netherConfig);
}

NetherPolicyBackend *NetherManager::getPolicyBackend(const NetherConfig &netherConfig, const bool primary)
{
    switch (primary ? netherConfig.primaryBackendType : netherConfig.backupBackendType)
    {
        case cynaraBackend:
#ifdef HAVE_CYNARA
            return new NetherCynaraBackend(netherConfig);
#else
            return new NetherDummyBackend(netherConfig);
#endif
        case fileBackend:
            return new NetherFileBackend(netherConfig);
        case dummyBackend:
        default:
            return new NetherDummyBackend(netherConfig);
    }
}

bool NetherManager::verdictCast (const u_int32_t packetId, const NetherVerdict verdict)
{
    if (netherNetlink)
    {
        netherNetlink->setVerdict(packetId, verdict);
    }
    else
    {
        LOGE("Netlink subsystem is invalid, can't decide on packet");
        return (false);
    }

    return (true);
}

void NetherManager::packetReceived (const NetherPacket &packet)
{
    LOGD(packetToString(packet).c_str());

    if (netherPrimaryPolicyBackend && netherPrimaryPolicyBackend->enqueueVerdict (packet))
    {
        LOGD("Primary policy accepted packet");
        return;
    }

    if (netherBackupPolicyBackend && netherBackupPolicyBackend->enqueueVerdict (packet))
    {
        LOGI("Primary policy backend failed, using backup policy backend");
        return;
    }

    /* In this situation no policy backend wants to deal with this packet
        there propably isn't any rule in either of them

        we need to make a generic decision based on whatever is hard-coded
        or passed as a parameter to the service */
    LOGW("All policy backends failed, using DUMMY backend");
    netherFallbackPolicyBackend->enqueueVerdict (packet);
}
