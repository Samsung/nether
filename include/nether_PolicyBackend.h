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
 * @brief   definition of a policy backend class
 */

#ifndef NETHER_POLICY_BACKEND_H
#define NETHER_POLICY_BACKEND_H

#include "nether_Types.h"
#include "nether_Utils.h"

class NetherPolicyBackend : public NetherVerdictCaster
{
    public:
        NetherPolicyBackend(const NetherConfig &_netherConfig) : netherConfig(_netherConfig) {}
        virtual ~NetherPolicyBackend() {}
        virtual const bool enqueueVerdict (const NetherPacket &packet) = 0;
        virtual const bool initialize() = 0;
        virtual const bool reload() { return (true); };
        virtual const bool isValid() = 0;
        virtual const int getDescriptor() { return (-1); }
        virtual const NetherDescriptorStatus getDescriptorStatus() { return (unknownStatus); }
        virtual const bool processEvents() = 0;

    protected:
        NetherConfig netherConfig;
};

#endif
