/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Roman Kubiak (r.kubiak@samsung.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */

/**
 * @file
 * @author  Roman Kubiak (r.kubiak@samsung.com)
 * @brief   Manager class implementation for nether
 */

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
    netherNetlink               = std::unique_ptr<NetherNetlink> (new NetherNetlink(netherConfig));
    netherNetlink->setListener (this);

    netherPrimaryPolicyBackend	= std::unique_ptr<NetherPolicyBackend> (getPolicyBackend (netherConfig));
    netherPrimaryPolicyBackend->setListener (this);

    netherBackupPolicyBackend   = std::unique_ptr<NetherPolicyBackend> (getPolicyBackend (netherConfig, false));
    netherBackupPolicyBackend->setListener (this);

    netherFallbackPolicyBackend = std::unique_ptr<NetherPolicyBackend> (new NetherDummyBackend(netherConfig));
}

NetherManager::~NetherManager()
{
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

    if (netherConfig.noRules == 0 && restoreRules() == false)
    {
        LOGE("Failed to setup iptables rules");
        return (false);
    }

#ifdef HAVE_AUDIT
    if (netherConfig.enableAudit)
    {
        if ( (auditDescriptor = audit_open ()) == -1)
        {
            LOGE("Failed to open an audit netlink socket: " << strerror(errno));
            return (false);
        }

        if (audit_set_enabled (auditDescriptor, 1) <= 0)
        {
            LOGE("Failed to enable auditing: " << strerror(errno));
            return (false);
        }
        else
        {
            LOGD("Auditing enabled");
        }
    }
#endif // HAVE_AUDIT

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
    fd_set watchedReadDescriptorsSet, watchedWriteDescriptorsSet;
    struct timeval timeoutSpecification;

    for (;;)
    {
	    setupSelectSockets (watchedReadDescriptorsSet, watchedWriteDescriptorsSet, timeoutSpecification);

        if (select (FD_SETSIZE, &watchedReadDescriptorsSet, &watchedWriteDescriptorsSet, NULL, &timeoutSpecification) < 0)
        {
            LOGE("select error " << strerror(errno));
            return (false);
        }

        if (FD_ISSET(signalDescriptor, &watchedReadDescriptorsSet))
        {
            handleSignal();
        }
        if (FD_ISSET(netlinkDescriptor, &watchedReadDescriptorsSet))
        {
            if (!handleNetlinkpacket())
                break;
        }
        else if (FD_ISSET(backendDescriptor, &watchedReadDescriptorsSet) || FD_ISSET(backendDescriptor, &watchedWriteDescriptorsSet))
        {
            netherPrimaryPolicyBackend->processEvents();
        }
        else
        {
            LOGD("select() timeout");
        }
    }
}

void NetherManager::handleSignal()
{
    LOGD("received signal");
    ssize_t signalRead;
    struct signalfd_siginfo signalfdSignalInfo;

    signalRead = read (signalDescriptor, &signalfdSignalInfo, sizeof(struct signalfd_siginfo));

    if (signalRead != sizeof(struct signalfd_siginfo))
    {
        LOGW("Received incomplete signal information, ignore");
        return;
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
    }
}

const bool NetherManager::handleNetlinkpacket()
{
    LOGD("netlink descriptor active");
    int packetReadSize;
    NetherPacket receivedPacket;
    char packetBuffer[NETHER_PACKET_BUFFER_SIZE] __attribute__ ((aligned));

    /* some data arrives on netlink, read it */
    if ((packetReadSize = recv(netlinkDescriptor, packetBuffer, sizeof(packetBuffer), 0)) >= 0)
    {
        /* try to process the packet using netfilter_queue library, fetch packet info
            needed for making a decision about it */
        if (netherNetlink->processPacket (packetBuffer, packetReadSize))
        {
            return (true);
        }
        else
        {
            /* if we can't process the incoming packets, it's bad. Let's exit now */
            LOGE("Failed to process netlink received packet, refusing to continue");
            return (false);
        }
    }

    if (packetReadSize < 0 && errno == ENOBUFS)
    {
        LOGI("NetherManager::process losing packets! [bad things might happen]");
        return (true);
    }

    LOGE("NetherManager::process recv failed " << strerror(errno));
    return (false);
}

void NetherManager::setupSelectSockets(fd_set &watchedReadDescriptorsSet, fd_set &watchedWriteDescriptorsSet, struct timeval &timeoutSpecification)
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
        if (netherPrimaryPolicyBackend->getDescriptorStatus() == NetherDescriptorStatus::readOnly)
        {
            FD_SET(backendDescriptor, &watchedReadDescriptorsSet);
        }
        else if (netherPrimaryPolicyBackend->getDescriptorStatus() == NetherDescriptorStatus::readWrite)
        {
            FD_SET(backendDescriptor, &watchedReadDescriptorsSet);
            FD_SET(backendDescriptor, &watchedWriteDescriptorsSet);
        }
    }

    timeoutSpecification.tv_sec     = 240;
    timeoutSpecification.tv_usec    = 0;
}

NetherConfig &NetherManager::getConfig()
{
    return (netherConfig);
}

NetherPolicyBackend *NetherManager::getPolicyBackend(const NetherConfig &netherConfig, const bool primary)
{
    switch (primary ? netherConfig.primaryBackendType : netherConfig.backupBackendType)
    {
        case NetherPolicyBackendType::cynaraBackend:
#ifdef HAVE_CYNARA
            return new NetherCynaraBackend(netherConfig);
#else
            return new NetherDummyBackend(netherConfig);
#endif
        case NetherPolicyBackendType::fileBackend:
            return new NetherFileBackend(netherConfig);
        case NetherPolicyBackendType::dummyBackend:
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

const bool NetherManager::restoreRules()
{
    if (!isCommandAvailable(netherConfig.iptablesRestorePath))
    {
        return (false);
    }

    std::stringstream cmdline;
    cmdline << netherConfig.iptablesRestorePath;
    cmdline << " ";
    cmdline << netherConfig.rulesPath;

    if (system (cmdline.str().c_str()))
    {
        LOGE("system() failed for: " << cmdline.str());
        return (false);
    }

    LOGD("iptables-restore succeeded with rules from: " << netherConfig.rulesPath);
    return (true);
}

const bool NetherManager::isCommandAvailable(const std::string &command)
{
    struct stat iptablesRestoreStat;

    if (stat(command.c_str(), &iptablesRestoreStat) == 0)
    {
        if (! iptablesRestoreStat.st_mode & S_IXUSR)
        {
            LOGE("Execute bit is not set for owner on:" << command);
            return (false);
        }

        return (true);
    }

    LOGE("Failed to stat command at: " << command << " error: " << strerror(errno));
    return (false);
}
