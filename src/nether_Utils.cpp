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
 * @brief   utility functions implementation
 */

#include "nether_Utils.h"

NetherVerdict stringToVerdict(char *verdictAsString)
{
	if(verdictAsString)
	{
		if(strncasecmp(verdictAsString, "allow_log", 9) == 0)
			return (NetherVerdict::allowAndLog);
		if(strncasecmp(verdictAsString, "allow", 6) == 0)
			return (NetherVerdict::allow);
		if(strncasecmp(verdictAsString, "deny", 4) == 0)
			return (NetherVerdict::deny);
	}
	return (NetherVerdict::allowAndLog);
}

NetherPolicyBackendType stringToBackendType(char *backendAsString)
{
	if(strcasecmp(backendAsString, "cynara") == 0)
		return (NetherPolicyBackendType::cynaraBackend);
	if(strcasecmp(backendAsString, "file") == 0)
		return (NetherPolicyBackendType::fileBackend);
	if(strcasecmp(backendAsString, "dummy") == 0)
		return (NetherPolicyBackendType::dummyBackend);

	return (NetherPolicyBackendType::dummyBackend);
}

NetherLogBackendType stringToLogBackendType(char *backendAsString)
{
	if(strcasecmp(backendAsString, "stderr") == 0)
		return (NetherLogBackendType::stderrBackend);
	if(strcasecmp(backendAsString, "syslog") == 0)
		return (NetherLogBackendType::syslogBackend);
	if(strcasecmp(backendAsString, "journal") == 0)
		return (NetherLogBackendType::journalBackend);
	if(strcasecmp(backendAsString, "file") == 0)
		return (NetherLogBackendType::logfileBackend);
	if(strcasecmp(backendAsString, "null") == 0)
		return (NetherLogBackendType::nullBackend);

	return (NetherLogBackendType::nullBackend);
}

std::string logBackendTypeToString(const NetherLogBackendType backendType)
{
	switch(backendType)
	{
		case NetherLogBackendType::stderrBackend:
			return ("stderr");
		case NetherLogBackendType::syslogBackend:
			return ("syslog");
		case NetherLogBackendType::journalBackend:
			return ("journal");
		case NetherLogBackendType::logfileBackend:
			return ("file");
		case NetherLogBackendType::nullBackend:
			return ("null");
	}
	return ("null");
}

std::string backendTypeToString(const NetherPolicyBackendType backendType)
{
	switch(backendType)
	{
		case NetherPolicyBackendType::cynaraBackend:
			return ("cynara");
		case NetherPolicyBackendType::fileBackend:
			return ("file");
		case NetherPolicyBackendType::dummyBackend:
		default:
			return ("dummy");
	}
}

std::string verdictToString(const NetherVerdict verdict)
{
	switch(verdict)
	{
		case NetherVerdict::allow:
			return ("ALLOW");
		case NetherVerdict::allowAndLog:
			return ("ALLOW_LOG");
		case NetherVerdict::deny:
			return ("DENY");
		case NetherVerdict::noVerdictYet:
			return ("NO_VERDICT_YET");
	}
	return ("NO_VERDICT_YET");
}

std::string transportToString(const NetherTransportType transportType)
{
	switch(transportType)
	{
		case NetherTransportType::TCP:
			return ("TCP");
		case NetherTransportType::UDP:
			return ("UDP");
		case NetherTransportType::ICMP:
			return ("ICMP");
		case NetherTransportType::IGMP:
			return ("IGMP");
		case NetherTransportType::unknownTransportType:
		default:
			return ("(unknown)");
	}
}

std::string protocolToString(const NetherProtocolType protocolType)
{
	switch(protocolType)
	{
		case NetherProtocolType::IPv4:
			return ("IPv4");
		case NetherProtocolType::IPv6:
			return ("IPv6");
		default:
			return ("(unknown)");
	}
}

std::string packetToString(const NetherPacket &packet)
{
	std::stringstream stream;
	stream << "ID=";
	stream << packet.id;
	stream << " SECCTX=";
	stream << packet.securityContext;
	stream << " OUTDEV=";
	stream << packet.outdevName;
	stream << " UID=";
	stream << packet.uid;
	stream << " GID=";
	stream << packet.gid;
	stream << " PROTO=";
	stream << protocolToString(packet.protocolType);
	stream << " TRANSPORT=";
	stream << transportToString(packet.transportType);
	stream << " SADDR=";
	stream << ipAddressToString(&packet.localAddress[0], packet.protocolType);
	stream << ":";
	stream << packet.localPort;
	stream << " DADDR=";
	stream << ipAddressToString(&packet.remoteAddress[0], packet.protocolType);
	stream << ":";
	stream << packet.remotePort;
	return (stream.str());
}
