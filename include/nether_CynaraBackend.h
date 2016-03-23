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
 * @brief   Cynara policy backend for nether
 */

#ifndef NETHER_CYNARA_BACKEND_H
#define NETHER_CYNARA_BACKEND_H

// #ifdef HAVE_CYNARA

#include <cynara-client-async.h>
#include "nether_PolicyBackend.h"
#include <vector>
#include <fstream>
#include <map>

#ifndef NETHER_CYNARA_INTERNET_PRIVILEGE
#define NETHER_CYNARA_INTERNET_PRIVILEGE "http://tizen.org/privilege/internet"
#endif // NETHER_CYNARA_INTERNET_PRIVILEGE

class NetherManager;

const std::string cynaraErrorCodeToString(int cynaraErrorCode);
typedef std::pair<std::string, u_int32_t> PrivilegePair;

struct NetherCynaraCheckInfo
{
	NetherCynaraCheckInfo() {}
	NetherCynaraCheckInfo(NetherPacket _packet, u_int32_t _privilegeId)
		: packet(_packet),
		  privilegeId(_privilegeId){}

	NetherCynaraCheckInfo& operator=(const NetherCynaraCheckInfo &other)
	{
		packet = other.packet;
		privilegeId = other.privilegeId;

		return *this;
	}

	NetherPacket packet;
	u_int32_t privilegeId = -1;
};

class NetherCynaraBackend : public NetherPolicyBackend
{
	public:
		NetherCynaraBackend(const NetherConfig &netherConfig);
		~NetherCynaraBackend();
		bool initialize();
		bool enqueueVerdict(const NetherPacket &packet);
		bool reEnqueVerdict(cynara_check_id checkId);
		bool cynaraCheck(NetherCynaraCheckInfo checkInfo);
		bool processEvents();
		int getDescriptor();
		bool parseInternalPolicy(const std::string &policyFile);
		NetherDescriptorStatus getDescriptorStatus();
		void setCynaraDescriptor(const int _currentCynaraDescriptor, const NetherDescriptorStatus _currentCynaraDescriptorStatus);
		void setCynaraVerdict(cynara_check_id checkId, int cynaraResult);
		static void statusCallback(int oldFd, int newFd, cynara_async_status status, void *data);
		static void checkCallback(cynara_check_id check_id, cynara_async_call_cause cause, int response, void *data);

	private:
		void parseBackendArgs();
		void setCacheSize(const size_t newCacheSize);
		cynara_async *cynaraContext;
		NetherDescriptorStatus currentCynaraDescriptorStatus;
		int currentCynaraDescriptor;
		int cynaraLastResult;
		cynara_async_configuration *cynaraConfig;
		std::map<cynara_check_id, NetherCynaraCheckInfo> responseQueue;
		std::vector<PrivilegePair> privilegeChain;
		u_int32_t allPrivilegesToCheck;
};

// #endif // HAVE_CYNARA
#endif // NETHER_CYNARA_BACKEND_H
