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
 * @brief   Dummy policy backend
 */
#ifndef NETHER_DUMMY_BACKEND_H
#define NETHER_DUMMY_BACKEND_H


#include "nether_PolicyBackend.h"

class NetherDummyBackend : public NetherPolicyBackend
{
    public:
        NetherDummyBackend(const NetherConfig &netherConfig)
            : NetherPolicyBackend(netherConfig) {}
        ~NetherDummyBackend() {}

        const bool isValid()
        {
            return (true);
        }

        const bool initialize()
        {
            return (true);
        }

        const bool enqueueVerdict(const NetherPacket &packet)
        {
            return (castVerdict (packet, netherConfig.defaultVerdict));
        }

        const bool processEvents()
        {
            return (true);
        }
};

#endif
