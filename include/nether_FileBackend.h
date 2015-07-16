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

#ifndef NETHER_FILE_BACKEND_H
#define NETHER_FILE_BACKEND_H

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <tuple>

#include "nether_PolicyBackend.h"

#define NETHER_POLICY_CREDS_DELIM   ":"

class NetherManager;

enum PolicyFileTokens
{
    uidT,
    gidT,
    secctxT,
    verdictT
};

struct PolicyEntry
{
    uid_t uid;
    gid_t gid;
    std::string securityContext;
    NetherVerdict verdict;
};

static const std::string dumpPolicyEntry(const PolicyEntry &entry)
{
    std::stringstream stream;
    stream << "UID=";
    if (entry.uid == NETHER_INVALID_UID) stream << "*"; else stream << entry.uid;
    stream << " GID=";
    if (entry.gid == NETHER_INVALID_GID) stream << "*"; else stream << entry.gid;
    stream << " SECCTX=";
    if (entry.securityContext.empty()) stream << "*"; else stream << entry.securityContext;
    stream << " VERDICT=";
    stream << verdictToString(entry.verdict);

    return (stream.str());
}

class NetherFileBackend : public NetherPolicyBackend
{
    public:
        NetherFileBackend(const NetherConfig &netherConfig);
        ~NetherFileBackend();
        const bool isValid();
        const bool initialize();
        const bool reload();
        const bool enqueueVerdict(const NetherPacket &packet);
        const bool parsePolicyFile(std::ifstream &policyFile);
        const bool processEvents() { return (true); }
        std::vector<std::string> split(const std::string  &str, const std::string  &delim);
    private:
        std::vector<PolicyEntry> policy;
};

#endif
