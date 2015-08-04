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
 * @brief   File policy backend for nether
 */

#include "nether_FileBackend.h"

const std::string dumpPolicyEntry(const PolicyEntry &entry)
{
	std::stringstream stream;
	stream << "UID=";
	if(entry.uid == NETHER_INVALID_UID)
		stream << "*";
	else
		stream << entry.uid;
	stream << " GID=";
	if(entry.gid == NETHER_INVALID_GID)
		stream << "*";
	else stream << entry.gid;
		stream << " SECCTX=";
	if(entry.securityContext.empty())
		stream << "*";
	else
		stream << entry.securityContext;
	stream << " VERDICT=";
	stream << verdictToString(entry.verdict);

	return (stream.str());
}

NetherFileBackend::NetherFileBackend(const NetherConfig &netherConfig)
	: NetherPolicyBackend(netherConfig)
{
}

NetherFileBackend::~NetherFileBackend()
{
}

bool NetherFileBackend::initialize()
{
	std::ifstream policyFile;
	policyFile.open(netherConfig.backupBackendArgs, std::ifstream::in);

	if(!policyFile)
	{
		LOGE("Can't open policy file at: " << netherConfig.backupBackendArgs);
		return (false);
	}

	return (parsePolicyFile(policyFile));
}

bool NetherFileBackend::reload()
{
	return (initialize());
}

bool NetherFileBackend::enqueueVerdict(const NetherPacket &packet)
{
	for(auto &policyIterator : policy)
	{
		if(
			((policyIterator.uid == packet.uid) || policyIterator.uid == NETHER_INVALID_UID) &&
			((policyIterator.gid == packet.gid) || policyIterator.gid == NETHER_INVALID_GID) &&
			((policyIterator.securityContext == packet.securityContext) || policyIterator.securityContext.empty())
		)
		{
			LOGD("policy match " << dumpPolicyEntry(policyIterator));
			return (castVerdict(packet, policyIterator.verdict));
		}
	}

	return (castVerdict(packet, netherConfig.defaultVerdict));
}

bool NetherFileBackend::parsePolicyFile(std::ifstream &policyFile)
{
	std::string line;
	std::vector<std::string> tokens;
	policy.clear();

	while(!policyFile.eof())
	{
		getline(policyFile, line);
		if(line[0] == '#' || line.empty() || !line.find(NETHER_POLICY_CREDS_DELIM, 0))
			continue;

		tokens = split(line, NETHER_POLICY_CREDS_DELIM);

		if(tokens.size() > 0 && tokens.size() > verdictToken)
		{
			PolicyEntry entry { tokens[PolicyFileTokens::uidToken].empty() ?
									NETHER_INVALID_UID :
									(uid_t)strtol(tokens[PolicyFileTokens::uidToken].c_str(), NULL, 10),
								tokens[PolicyFileTokens::gidToken].empty() ?
									NETHER_INVALID_GID :
									(gid_t)strtol(tokens[PolicyFileTokens::gidToken].c_str(), NULL, 10),
								tokens[PolicyFileTokens::secctxToken],
								stringToVerdict((char *)tokens[PolicyFileTokens::verdictToken].c_str())
							  };

			LOGD("\t"<<dumpPolicyEntry(entry).c_str());
			policy.push_back(entry);
		}
		else
		{
			LOGW("Malformed policy entry: " + line + " in file: " + netherConfig.backupBackendArgs);
		}
	}

	return (true);
}

std::vector<std::string> NetherFileBackend::split(const std::string &str, const std::string &delim)
{
	std::vector<std::string> tokens;
	size_t  start = 0, end = 0;

	while(end != std::string::npos)
	{
		end = str.find(delim, start);

		// If at end, use length=maxLength.  Else use length=end-start.
		tokens.push_back(str.substr(start, (end == std::string::npos) ? std::string::npos : end - start));

		// If at end, use start=maxSize.  Else use start=end+delimiter.
		start = ((end > (std::string::npos - delim.size())) ?  std::string::npos  :  end + delim.size());
	}

	return (tokens);
}
