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

#include "nether_CynaraBackend.h"
#include "nether_Utils.h"

#include <fstream>

using namespace std;

#ifdef HAVE_CYNARA

const std::string cynaraErrorCodeToString(int cynaraErrorCode)
{
	char errorString[512];
	int ret;

	if((ret = cynara_strerror(cynaraErrorCode, errorString, 512)) == CYNARA_API_SUCCESS)
		return (std::string(errorString, strlen(errorString)));
	else
		return ("Failed to get error string representation, code="+ret);
}

NetherCynaraBackend::NetherCynaraBackend(const NetherConfig &netherConfig)
	:   NetherPolicyBackend(netherConfig), currentCynaraDescriptor(0),
		cynaraLastResult(CYNARA_API_UNKNOWN_ERROR), cynaraConfig(nullptr),
		allPrivilegesToCheck(1) /* if there is no additional policy, only one check is done */
{
	/* This is the default, if no policy is defined in the file or no
		privilege name is passed in the command line, the built in
		or the one defined at build time will be used
		-1 is the mark that means, ACCEPT (don't mark the packet at all) */
	privilegeChain.push_back (PrivilegePair (NETHER_CYNARA_INTERNET_PRIVILEGE, -1));

	if (netherConfig.primaryBackendArgs.length() != 0)
	{
		parseBackendArgs();
	}
}

NetherCynaraBackend::~NetherCynaraBackend()
{
	cynara_async_configuration_destroy(cynaraConfig);
}

bool NetherCynaraBackend::initialize()
{
	cynaraLastResult  = cynara_async_initialize(&cynaraContext, cynaraConfig, &statusCallback, this);
	if(cynaraLastResult != CYNARA_API_SUCCESS)
	{
		LOGE("Failed to initialize cynara client " << cynaraErrorCodeToString(cynaraLastResult));
		return (false);
	}

	return (true);
}

void NetherCynaraBackend::statusCallback(int , int newFd, cynara_async_status status, void *data)
{
	NetherCynaraBackend *backend = static_cast<NetherCynaraBackend *>(data);

	if(status == CYNARA_STATUS_FOR_READ)
		backend->setCynaraDescriptor(newFd, NetherDescriptorStatus::readOnly);

	if(status == CYNARA_STATUS_FOR_RW)
		backend->setCynaraDescriptor(newFd, NetherDescriptorStatus::readWrite);
}

void NetherCynaraBackend::checkCallback(cynara_check_id check_id,
										cynara_async_call_cause cause,
										int response,
										void *data)
{
	NetherCynaraBackend *backend = static_cast<NetherCynaraBackend *>(data);

	if(cause == CYNARA_CALL_CAUSE_ANSWER)
		backend->setCynaraVerdict(check_id, response);
	else
		LOGI("unknown reason for call cause="<< cause <<" response="<< response);
}

bool NetherCynaraBackend::cynaraCheck(NetherCynaraCheckInfo checkInfo)
{
	cynaraLastResult = cynara_async_check_cache(cynaraContext,
												checkInfo.packet.securityContext.c_str(),
												"",
												std::to_string(checkInfo.packet.uid).c_str(),
												privilegeChain[checkInfo.privilegeId].first.c_str());

	LOGD("cynara_async_check_cache ctx=" << checkInfo.packet.securityContext.c_str()
										 << " user="
										 << std::to_string(checkInfo.packet.uid).c_str()
										 << " privilege="
										 << privilegeChain[checkInfo.privilegeId].first
										 << " mark="
										 << privilegeChain[checkInfo.privilegeId].second
										 << " result string=\""
										 << cynaraErrorCodeToString(cynaraLastResult)
										 << "\""
										 << " packetId="
										 << checkInfo.packet.id);

	switch(cynaraLastResult)
	{
		case CYNARA_API_ACCESS_ALLOWED:
			return (castVerdict(checkInfo.packet,
								NetherVerdict::allow,
								privilegeChain[checkInfo.privilegeId].second));

		case CYNARA_API_ACCESS_DENIED:
			/* We need to copy this into the queue
				other checks might be needed
				and this information will be necessary */

			responseQueue[checkInfo.checkId] = checkInfo;
			return (reEnqueVerdict(checkInfo.checkId));

		case CYNARA_API_CACHE_MISS:
			cynaraLastResult = cynara_async_create_request(cynaraContext,
							   checkInfo.packet.securityContext.c_str(),
							   "",
							   std::to_string(checkInfo.packet.uid).c_str(),
							   privilegeChain[checkInfo.privilegeId].first.c_str(),
							   &checkInfo.checkId,
							   &checkCallback,
							   this);

			if(cynaraLastResult == CYNARA_API_SUCCESS)
			{
				responseQueue[checkInfo.checkId] = checkInfo;
				return (true);
			}
			else
			{
				if(cynaraLastResult == CYNARA_API_SERVICE_NOT_AVAILABLE)
				{
					LOGW("Cynara offline, fall back to another backend");
					return (false);
				}
				else
				{
					LOGW("Error on cynara request create after CYNARA_API_CACHE_MISS " << cynaraErrorCodeToString(cynaraLastResult));
					return (false);
				}
			}

		default:
			LOGW("Error on cynara request create unhandled result from cynara_async_check_cache "<<cynaraErrorCodeToString(cynaraLastResult));
			return (false);
	}

	return (true);
}

bool NetherCynaraBackend::enqueueVerdict(const NetherPacket &packet)
{
	LOGD("packet id=" << packet.id);
	return (cynaraCheck (NetherCynaraCheckInfo(packet, 0)));
}

bool NetherCynaraBackend::reEnqueVerdict(cynara_check_id checkId)
{
	NetherCynaraCheckInfo checkInfo = responseQueue[checkId];

	/* We got deny from cynara, we need to check
		if our internal policy
		has other entries and try them too */
	if (++checkInfo.privilegeId < allPrivilegesToCheck)
	{
		LOGD("more privileges in policy, keep checking id=" << checkInfo.packet.id);
		return (cynaraCheck(checkInfo));
	}
	else
	{
		LOGD("policy exhausted, deny packet id=" << checkInfo.packet.id);
		return (castVerdict(checkInfo.packet.id, NetherVerdict::deny));
	}
}

void NetherCynaraBackend::setCynaraVerdict(cynara_check_id checkId, int cynaraResult)
{
	NetherCynaraCheckInfo checkInfo = responseQueue[checkId];

	if(cynaraResult == CYNARA_API_ACCESS_ALLOWED)
	{
		castVerdict(checkInfo.packet.id,
					NetherVerdict::allow,
					privilegeChain[checkInfo.privilegeId].second);
	}
	else
	{
		if (!reEnqueVerdict(checkId))
		{
			LOGE("reEnqueueVerdict failed");
		}
	}
}

int NetherCynaraBackend::getDescriptor()
{
	return (currentCynaraDescriptor);
}

NetherDescriptorStatus NetherCynaraBackend::getDescriptorStatus()
{
	return (currentCynaraDescriptorStatus);
}

void NetherCynaraBackend::setCynaraDescriptor(const int _currentCynaraDescriptor, const NetherDescriptorStatus _currentCynaraDescriptorStatus)
{
	currentCynaraDescriptorStatus   = _currentCynaraDescriptorStatus;
	currentCynaraDescriptor         = _currentCynaraDescriptor;
}

bool NetherCynaraBackend::processEvents()
{
	int ret = cynara_async_process(cynaraContext);

	if(ret == CYNARA_API_SUCCESS)
		return (true);

	LOGW("cynara_async_process failed " << cynaraErrorCodeToString(ret));
	return (false);
}

void NetherCynaraBackend::setCacheSize(const size_t newCacheSize)
{
	int ret;

	if ((ret = cynara_async_configuration_create (&cynaraConfig)) != CYNARA_API_SUCCESS)
	{
		LOGE("cynara_async_configuration_create failed: " << cynaraErrorCodeToString(ret));
	}

	if ((ret = cynara_async_configuration_set_cache_size(cynaraConfig, newCacheSize)) != CYNARA_API_SUCCESS)
	{
		LOGE("cynara_async_configuration_set_cache_size failed: " << cynaraErrorCodeToString(ret));
	}

	LOGD("New cache size: " << newCacheSize);
}

void NetherCynaraBackend::parseBackendArgs()
{
	vector<string> valueNamePairs = tokenize(netherConfig.primaryBackendArgs,";");

	for (vector<string>::iterator it = valueNamePairs.begin(); it != valueNamePairs.end(); ++it)
	{
		vector<string> valueNamePair = tokenize(*it, "=");

		if (valueNamePair[0] == "cache-size")
		{
			std::string::size_type sz;
			setCacheSize (stoi (valueNamePair[1], &sz, 10));
		}

		if (valueNamePair[0] == "policy")
		{
			parseInternalPolicy (valueNamePair[1]);
		}

		if (valueNamePair[0] == "privname")
		{
			privilegeChain.clear();
			privilegeChain.push_back (PrivilegePair (valueNamePair[1], -1));
		}
	}
}

bool NetherCynaraBackend::parseInternalPolicy(const std::string &policyFile)
{
	privilegeChain.clear();
	allPrivilegesToCheck = 0;

	std::ifstream policyStream (policyFile);

	if (!policyStream.good())
	{
		LOGE("Cynara policy file: " << policyFile << " failed to open. Using default privilege: \""
									<< privilegeChain[0].first << "\" for security checks");
		return (false);
	}

	std::string s, privname, mark;
	while (std::getline (policyStream,s))
	{
		std::string::size_type begin = s.find_first_not_of( " \f\t\v" );

		// Skip blank lines
		if (begin == std::string::npos) continue;

		// Skip commentary
		if (std::string( "#;" ).find( s[ begin ] ) != std::string::npos) continue;

		// Extract the key value
		std::string::size_type end = s.find( '|', begin );
		privname = s.substr( begin, end - begin );

		// (No leading or trailing whitespace allowed)
		privname.erase( privname.find_last_not_of( " \f\t\v" ) + 1 );

		// No blank keys allowed
		if (privname.empty()) continue;

		// Extract the value (no leading or trailing whitespace allowed)
		begin = s.find_first_not_of( " \f\n\r\t\v", end + 1 );
		end   = s.find_last_not_of(  " \f\n\r\t\v" ) + 1;
		mark = s.substr( begin, end - begin );

		// Insert the properly extracted (key, value) pair into the map
		LOGD("cynara policy add privilege: " << privname << " mark:" << mark);
		privilegeChain.push_back(PrivilegePair(privname, std::stoi(mark, 0, 16)));
	}

	/* In case we didn't get at least ONE privilege from the file
		fall back to default */
	if (privilegeChain.size() == 0)
		privilegeChain.push_back (PrivilegePair (NETHER_CYNARA_INTERNET_PRIVILEGE, -1));

	allPrivilegesToCheck = privilegeChain.size();
	return (true);
}
#endif
