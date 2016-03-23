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
		bool initialize();
		bool process();
		NetherConfig &getConfig();
		static NetherPolicyBackend *getPolicyBackend(const NetherConfig &netherConfig, const bool primary = true);
		bool verdictCast(const u_int32_t packetId, const NetherVerdict verdict, int mark);
		void packetReceived(const NetherPacket &packet);
		bool restoreRules();

	private:
		static bool isCommandAvailable(const std::string &command);
		void handleSignal();
		bool handleNetlinkpacket();
		void setupSelectSockets(fd_set &watchedReadDescriptorsSet, fd_set &watchedWriteDescriptorsSet, struct timeval &timeoutSpecification);
		std::unique_ptr <NetherPolicyBackend> netherPrimaryPolicyBackend;
		std::unique_ptr <NetherPolicyBackend> netherBackupPolicyBackend;
		std::unique_ptr <NetherPolicyBackend> netherFallbackPolicyBackend;
		std::unique_ptr <NetherNetlink> netherNetlink;
		NetherConfig netherConfig;
		int netlinkDescriptor;
		int backendDescriptor;
		int signalDescriptor;
#ifdef HAVE_AUDIT
		int auditDescriptor;
#endif // HAVE_AUDIT
		sigset_t signalMask;
};

#endif
