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
 * @brief   netlink handler class for nether
 */

#ifndef NETHER_NETLINK_H
#define NETHER_NETLINK_H

#include "nether_Types.h"
#include "nether_Utils.h"

class NetherManager;

class NetherNetlink : public NetherPacketProcessor
{
	public:
		NetherNetlink(NetherConfig &netherConfig);
		~NetherNetlink();
		bool initialize();
		bool reload();
		static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
		bool processPacket(char *packetBuffer, const int packetReadSize);
		void setVerdict(const u_int32_t packetId, const NetherVerdict verdict, int32_t mark = -1);
		int getDescriptor();
		const NetherConfig &getNetherConfig();
		void getInterfaceInfo(struct nfq_data *nfa, NetherPacket &netherPacket);

	protected:
		NetherPacket *processedPacket;

	private:
		struct nfq_q_handle *queueHandle;
		struct nfq_handle *nfqHandle;
		struct nlif_handle *nlif;
		uint32_t queue;
};

#endif  // NETLINK_H_INCLUDED
