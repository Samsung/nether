/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @brief   types used in nether
 */


#ifndef NETHER_TYPES_H
#define NETHER_TYPES_H

#include <iostream>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <memory>

#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <strings.h>
#include <getopt.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/signalfd.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "logger/logger.hpp"
#include "logger/backend-file.hpp"
#include "logger/backend-stderr.hpp"
#include "logger/backend-syslog.hpp"

#ifdef HAVE_CYNARA
 #define NETHER_PRIMARY_BACKEND          cynaraBackend
 #define NETHER_BACKUP_BACKEND           fileBackend
#else
 #define NETHER_PRIMARY_BACKEND          fileBackend
 #define NETHER_BACKUP_BACKEND           dummyBackend
#endif

#define NETHER_DEFAULT_VERDICT          allowAndLog
#define NETHER_PACKET_BUFFER_SIZE       4096
#define NETHER_INVALID_UID              (uid_t) -1
#define NETHER_INVALID_GID              (gid_t) -1
#define NETHER_NETWORK_ADDR_LEN         16 /* enough to hold ipv4 and ipv6 */
#define NETHER_NETWORK_IPV4_ADDR_LEN    4
#define NETHER_NETWORK_IPV6_ADDR_LEN    16
#define NETHER_MAX_USER_LEN             32
#define NETLINK_DROP_MARK               3
#define NETLINK_ALLOWLOG_MARK           4
#define NETHER_LOG_BACKEND              stderrBackend

enum NetherPolicyBackendType
{
    cynaraBackend,
    fileBackend,
    dummyBackend
};

enum NetherLogBackendType
{
    stderrBackend,
    syslogBackend,
    journalBackend,
    logfileBackend,
    nullBackend
};

enum NetherVerdict
{
    allow,
    allowAndLog,
    deny,
    noVerdictYet
};

enum NetherDescriptorStatus
{
    readOnly,
    writeOnly,
    readWrite,
    unknownStatus
};

enum NetherTransportType
{
    TCP,
    UDP,
    ICMP,
    IGMP,
    unknownTransportType
};

enum NetherProtocolType
{
    IPv4,
    IPv6,
    unknownProtocolType
};


struct NetherPacket
{
    u_int32_t id;
    std::string securityContext;
    uid_t uid;
    gid_t gid;
    pid_t pid;
    NetherTransportType transportType;
    NetherProtocolType protocolType;
    char localAddress[NETHER_NETWORK_ADDR_LEN];
    int localPort;
    char remoteAddress[NETHER_NETWORK_ADDR_LEN];
    int remotePort;
};

struct NetherConfig
{
    NetherVerdict defaultVerdict                = NETHER_DEFAULT_VERDICT;
    NetherPolicyBackendType primaryBackendType  = NETHER_PRIMARY_BACKEND;
    NetherPolicyBackendType backupBackendType   = NETHER_BACKUP_BACKEND;
    NetherLogBackendType logBackend             = NETHER_LOG_BACKEND;
    int primaryBackendRetries                   = 3;
    int backupBackendRetries                    = 3;
    int debugMode                               = 0;
    int nodaemonMode                            = 0;
    int queueNumber                             = 0;
    std::string backupBackendArgs;
    std::string primaryBackendArgs;
    std::string logBackendArgs;
    uint8_t markDeny                            = NETLINK_DROP_MARK;
    uint8_t markAllowAndLog                     = NETLINK_ALLOWLOG_MARK;
};

class NetherVerdictListener
{
    public:
        virtual bool verdictCast (const u_int32_t packetId, const NetherVerdict verdict) = 0;
};

class NetherVerdictCaster
{
    public:
        NetherVerdictCaster() : verdictListener(nullptr) {}
        virtual ~NetherVerdictCaster() {}

        void setListener(NetherVerdictListener *listenerToSet)
        {
            verdictListener = listenerToSet;
        }

        bool castVerdict (const NetherPacket &packet, const NetherVerdict verdict)
        {
            if (verdictListener)
                return (verdictListener->verdictCast(packet.id, verdict));
            return (false);
        }

        bool castVerdict (const u_int32_t packetId, const NetherVerdict verdict)
        {
            if (verdictListener)
                return (verdictListener->verdictCast(packetId, verdict));
            return (false);
        }

    protected:
        NetherVerdictListener *verdictListener;
};

class NetherProcessedPacketListener
{
    public:
        virtual void packetReceived (const NetherPacket &packet) = 0;
};

class NetherPacketProcessor
{
    public:
        NetherPacketProcessor(NetherConfig &_netherConfig) : netherConfig(_netherConfig), packetListener(nullptr) {}
        virtual ~NetherPacketProcessor() {}
        virtual const bool reload() { return (true); }
        void setListener(NetherProcessedPacketListener *listenerToSet)
        {
            packetListener = listenerToSet;
        }

        void processNetherPacket (NetherPacket packetInfoToWrite)
        {
            if (packetListener) packetListener->packetReceived(packetInfoToWrite);
        }

        virtual void setVerdict(const NetherPacket &packet, const NetherVerdict verdict) {}
    protected:
        NetherProcessedPacketListener *packetListener;
        NetherConfig netherConfig;
};
#endif
