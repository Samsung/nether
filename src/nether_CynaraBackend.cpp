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
	:   NetherPolicyBackend(netherConfig), currentCynaraDescriptor(-1),
		cynaraLastResult(CYNARA_API_UNKNOWN_ERROR)
{
	responseQueue.reserve(1024);
}

NetherCynaraBackend::~NetherCynaraBackend()
{
}

bool NetherCynaraBackend::initialize()
{
	cynaraLastResult  = cynara_async_initialize(&cynaraContext, NULL, &statusCallback, this);
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

bool NetherCynaraBackend::enqueueVerdict(const NetherPacket &packet)
{
	cynara_check_id checkId;

	cynaraLastResult = cynara_async_check_cache(cynaraContext,
												packet.securityContext.c_str(),
												"",
												std::to_string(packet.uid).c_str(),
												NETHER_CYNARA_INTERNET_PRIVILEGE);

	LOGD("cynara_async_check_cache ctx=" << packet.securityContext.c_str() << " user=" << std::to_string(packet.uid).c_str() << " privilege=" << NETHER_CYNARA_INTERNET_PRIVILEGE);

	switch(cynaraLastResult)
	{
		case CYNARA_API_ACCESS_ALLOWED:
			LOGD(cynaraErrorCodeToString(cynaraLastResult).c_str());
			return (castVerdict(packet, NetherVerdict::allow));

		case CYNARA_API_ACCESS_DENIED:
			LOGD(cynaraErrorCodeToString(cynaraLastResult).c_str());
			return (castVerdict(packet, NetherVerdict::deny));

		case CYNARA_API_CACHE_MISS:
			cynaraLastResult = cynara_async_create_request(cynaraContext,
							   packet.securityContext.c_str(),
							   "",
							   std::to_string(packet.uid).c_str(),
							   NETHER_CYNARA_INTERNET_PRIVILEGE,
							   &checkId,
							   &checkCallback,
							   this);

			if(cynaraLastResult == CYNARA_API_SUCCESS)
			{
				responseQueue[checkId] = packet.id;

				return (true);
			}
			else
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

		default:
			LOGW("Error on cynara request create unhandled result from cynara_async_check_cache "<<cynaraErrorCodeToString(cynaraLastResult));
			return (false);
	}

	return (true);
}

void NetherCynaraBackend::setCynaraVerdict(cynara_check_id checkId, int cynaraResult)
{
	u_int32_t packetId = responseQueue[checkId];

	if(cynaraResult == CYNARA_API_ACCESS_ALLOWED)
		castVerdict(packetId, NetherVerdict::allow);
	else
		castVerdict(packetId, NetherVerdict::deny);

	return;
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
#endif
