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
 * @brief   types used in nether
 */


#ifndef NETHER_TYPES_H
#define NETHER_TYPES_H

#include <iostream>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <memory>
#include <cstdint>
#include <vector>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <strings.h>
#include <getopt.h>
#include <assert.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/types.h>
#include <sys/signalfd.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#if defined(HAVE_AUDIT)
#include <libaudit.h>
#endif // HAVE_AUDIT

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "logger/logger.hpp"
#include "logger/backend-file.hpp"
#include "logger/backend-stderr.hpp"
#include "logger/backend-syslog.hpp"

#if defined(HAVE_SYSTEMD_JOURNAL)
#include "logger/backend-journal.hpp"
#endif // HAVE_SYSTEMD_JOURNAL

#if defined(HAVE_CYNARA)
#define NETHER_PRIMARY_BACKEND			NetherPolicyBackendType::cynaraBackend
#define NETHER_BACKUP_BACKEND			NetherPolicyBackendType::fileBackend
#else
#define NETHER_PRIMARY_BACKEND			NetherPolicyBackendType::fileBackend
#define NETHER_BACKUP_BACKEND			NetherPolicyBackendType::dummyBackend
#endif // HAVE_CYNARA

#if defined(COPY_PACKETS)
#define NETLINK_COPY_PACKETS			1
#else
#define NETLINK_COPY_PACKETS			0
#endif // COPY_PACKETS

#define NETLINK_INTERFACE_INFO			0

#ifndef NETHER_RULES_PATH
#define NETHER_RULES_PATH				"/etc/nether/nether.rules"
#endif // NETHER_RULES_PATH

#ifndef NETHER_POLICY_FILE
#define NETHER_POLICY_FILE				"/etc/nether/file.policy"
#endif // NETHER_POLICY_FILE


#define NETHER_DEFAULT_VERDICT			NetherVerdict::allowAndLog
#define NETHER_PACKET_BUFFER_SIZE		4096
#define NETHER_INVALID_UID				(uid_t) -1
#define NETHER_INVALID_GID				(gid_t) -1
#define NETHER_NETWORK_ADDR_LEN			16 /* enough to hold ipv4 and ipv6 */
#define NETHER_NETWORK_IPV4_ADDR_LEN	4
#define NETHER_NETWORK_IPV6_ADDR_LEN	16
#define NETHER_MAX_USER_LEN				32
#define NETLINK_DROP_MARK				3
#define NETLINK_ALLOWLOG_MARK			4
#define NETLINK_QUEUE_NUM				0
#define NETHER_LOG_BACKEND				NetherLogBackendType::stderrBackend
#define NETHER_IPTABLES_RESTORE_PATH	"/usr/sbin/iptables-restore"

enum class NetherPolicyBackendType : std::uint8_t
{
	cynaraBackend,
	fileBackend,
	dummyBackend
};

enum class NetherLogBackendType : std::uint8_t
{
	stderrBackend,
	syslogBackend,
	journalBackend,
	logfileBackend,
	nullBackend
};

enum class NetherVerdict : std::uint8_t
{
	allow,
	allowAndLog,
	deny,
	noVerdictYet
};

enum class NetherDescriptorStatus : std::uint8_t
{
	readOnly,
	writeOnly,
	readWrite,
	unknownStatus
};

enum class NetherTransportType : std::uint8_t
{
	TCP,
	UDP,
	ICMP,
	IGMP,
	unknownTransportType
};

enum class NetherProtocolType : std::uint8_t
{
	IPv4,
	IPv6,
	unknownProtocolType
};


struct NetherPacket
{
	uid_t uid;
	u_int32_t id;
	std::string securityContext;
	int32_t remotePort								= -1;
	int32_t localPort								= -1;
	gid_t gid;
	pid_t pid;
	char localAddress[NETHER_NETWORK_ADDR_LEN]		= {0};
	char remoteAddress[NETHER_NETWORK_ADDR_LEN]		= {0};
	NetherTransportType transportType;
	NetherProtocolType protocolType;
	char outdevName[IFNAMSIZ]						= {0};
};

struct NetherConfig
{
	NetherVerdict defaultVerdict				= NETHER_DEFAULT_VERDICT;
	NetherPolicyBackendType primaryBackendType	= NETHER_PRIMARY_BACKEND;
	NetherPolicyBackendType backupBackendType	= NETHER_BACKUP_BACKEND;
	NetherLogBackendType logBackend				= NETHER_LOG_BACKEND;
	uint8_t markDeny							= NETLINK_DROP_MARK;
	uint8_t markAllowAndLog						= NETLINK_ALLOWLOG_MARK;
	int primaryBackendRetries					= 3;
	int backupBackendRetries					= 3;
	int debugMode								= 0;
	int daemonMode								= 0;
	int queueNumber								= NETLINK_QUEUE_NUM;
	int enableAudit								= 0;
	int noRules									= 0;
	int copyPackets								= NETLINK_COPY_PACKETS;
	int relaxed									= 0;
	int interfaceInfo							= NETLINK_INTERFACE_INFO;
	std::string backupBackendArgs				= NETHER_POLICY_FILE;
	std::string rulesPath						= NETHER_RULES_PATH;
	std::string iptablesRestorePath				= NETHER_IPTABLES_RESTORE_PATH;
	std::string primaryBackendArgs;
	std::string logBackendArgs;
};

class NetherVerdictListener
{
	public:
		virtual ~NetherVerdictListener() = default;
		virtual bool verdictCast(const u_int32_t packetId, const NetherVerdict verdict, int mark) = 0;
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

		bool castVerdict(const NetherPacket &packet, const NetherVerdict verdict, const int32_t mark = -1)
		{
			if(verdictListener)
				return (verdictListener->verdictCast(packet.id, verdict, mark));
			return (false);
		}

		bool castVerdict(const u_int32_t packetId, const NetherVerdict verdict, const int32_t mark = -1)
		{
			if(verdictListener)
				return (verdictListener->verdictCast(packetId, verdict, mark));
			return (false);
		}

	protected:
		NetherVerdictListener *verdictListener;
};

class NetherProcessedPacketListener
{
	public:
		virtual ~NetherProcessedPacketListener() = default;
		virtual void packetReceived(const NetherPacket &packet) = 0;
};

class NetherPacketProcessor
{
	public:
		NetherPacketProcessor(NetherConfig &_netherConfig)
			: packetListener(nullptr), netherConfig(_netherConfig) {}
		virtual ~NetherPacketProcessor() {}
		virtual bool reload()
		{
			return (true);
		}
		void setListener(NetherProcessedPacketListener *listenerToSet)
		{
			packetListener = listenerToSet;
		}

		void processNetherPacket(NetherPacket packetInfoToWrite)
		{
			if(packetListener) packetListener->packetReceived(packetInfoToWrite);
		}

		virtual void setVerdict(const u_int32_t packetId, const NetherVerdict verdict, const int32_t mark = -1) = 0;

	protected:
		NetherProcessedPacketListener *packetListener;
		NetherConfig netherConfig;
};
#endif
