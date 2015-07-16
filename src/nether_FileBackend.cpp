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
 * @brief   File policy backend for nether
 */

#include "nether_FileBackend.h"

NetherFileBackend::NetherFileBackend (const NetherConfig &netherConfig)
    : NetherPolicyBackend(netherConfig)
{
}

NetherFileBackend::~NetherFileBackend()
{
}

const bool NetherFileBackend::isValid()
{
    return (true);
}

const bool NetherFileBackend::initialize()
{
    std::ifstream policyFile;
    policyFile.open (netherConfig.backupBackendArgs, std::ifstream::in);

    if (!policyFile)
    {
        LOGE("Can't open policy file at: " << netherConfig.backupBackendArgs);
        return (false);
    }

    return (parsePolicyFile(policyFile));
}

const bool NetherFileBackend::reload()
{
    return (initialize());
}

const bool NetherFileBackend::enqueueVerdict(const NetherPacket &packet)
{
    for (auto &policyIterator : policy)
    {
        if (
                ( (policyIterator.uid == packet.uid) || policyIterator.uid == NETHER_INVALID_UID ) &&
                ( (policyIterator.gid == packet.gid) || policyIterator.gid == NETHER_INVALID_GID ) &&
                ( (policyIterator.securityContext == packet.securityContext) || policyIterator.securityContext.empty() )
            )
        {
            LOGD("policy match " << dumpPolicyEntry(policyIterator));
            return (castVerdict(packet, policyIterator.verdict));
        }
    }

    return (false);
}

const bool NetherFileBackend::parsePolicyFile(std::ifstream &policyFile)
{
    std::string line;
    std::vector<std::string> tokens;
    policy.clear();

    while (!policyFile.eof())
    {
        getline(policyFile, line);
        if (line[0] == '#' || line.empty() || !line.find(NETHER_POLICY_CREDS_DELIM, 0))
            continue;

        tokens = split (line, NETHER_POLICY_CREDS_DELIM);

        if (tokens.size() > 0)
        {
            PolicyEntry entry { tokens[uidT].empty() ? NETHER_INVALID_UID : (uid_t)strtol(tokens[uidT].c_str(), NULL, 10),   /* uid */
                                tokens[gidT].empty() ? NETHER_INVALID_GID : (gid_t)strtol(tokens[gidT].c_str(), NULL, 10),   /* gid */
                                tokens[secctxT],                                                /* security context */
                                stringToVerdict((char *)tokens[verdictT].c_str())               /* verdict */
                            };

            LOGD("\t"<<dumpPolicyEntry(entry).c_str());
            policy.push_back(entry);
        }
    }

    return (true);
}

std::vector<std::string> NetherFileBackend::split(const std::string &str, const std::string &delim)
{
    std::vector<std::string> tokens;
    size_t  start = 0, end = 0;

    while (end != std::string::npos)
    {
        end = str.find(delim, start);

        // If at end, use length=maxLength.  Else use length=end-start.
        tokens.push_back(str.substr(start, (end == std::string::npos) ? std::string::npos : end - start));

        // If at end, use start=maxSize.  Else use start=end+delimiter.
        start = ((end > (std::string::npos - delim.size())) ?  std::string::npos  :  end + delim.size());
    }

    return (tokens);
}
