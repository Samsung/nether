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

#include "nether_Netlink.h"

NetherNetlink::NetherNetlink(NetherConfig &netherConfig)
	: NetherPacketProcessor(netherConfig), queueHandle(nullptr), nfqHandle(nullptr), nlif(nullptr), queue(netherConfig.queueNumber)
{
}

NetherNetlink::~NetherNetlink()
{
	if(queueHandle) nfq_destroy_queue(queueHandle);
	if(nfqHandle) nfq_close(nfqHandle);
}

bool NetherNetlink::initialize()
{
	nfqHandle = nfq_open();

	if(!nfqHandle)
	{
		LOGE("Error during nfq_open()");
		return (false);
	}

	if(nfq_unbind_pf(nfqHandle, AF_INET) < 0)
	{
		LOGE("Error during nfq_unbind_pf() (no permission?)");
		return (false);
	}

	if(nfq_bind_pf(nfqHandle, AF_INET) < 0)
	{
		LOGE("Error during nfq_bind_pf()");
		return (false);
	}

	queueHandle = nfq_create_queue(nfqHandle, queue, &callback, this);

	if(!queueHandle)
	{
		LOGE("Error during nfq_create_queue()");
		return (false);
	}

	if(nfq_set_queue_flags(queueHandle, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX))
		LOGI("This kernel version does not allow to retrieve security context");

	if(nfq_set_mode(queueHandle, netherConfig.copyPackets ? NFQNL_COPY_PACKET : NFQNL_COPY_META, 0xffff) < 0)
	{
		LOGE("Can't set packet_copy mode");
		nfq_destroy_queue(queueHandle);
		return (false);
	}

	if(nfq_set_queue_flags(queueHandle, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID))
	{
		LOGE("This kernel version does not allow to retrieve process UID/GID");
		nfq_destroy_queue(queueHandle);
		return (false);
	}

	if (netherConfig.interfaceInfo)
	{
		nlif = nlif_open();

		if(!nlif)
			LOGI("Failed to initialize NLIF subsystem, interface information won't be available");
		else
			nlif_query(nlif);
	}

	return (true);
}

int NetherNetlink::getDescriptor()
{
	if(nfqHandle)
		return (nfq_fd(nfqHandle));
	else
		LOGE("nfq not initialized");
	return (-1);
}

bool NetherNetlink::processPacket(char *packetBuffer, const int packetReadSize)
{
	if(nfq_handle_packet(nfqHandle, packetBuffer, packetReadSize))
	{
		LOGE("nfq_handle_packet failed");
		return (false);
	}

	return (true);
}

void NetherNetlink::getInterfaceInfo(struct nfq_data *nfa, NetherPacket &netherPacket)
{
	if (netherConfig.interfaceInfo)
	{
		uint32_t ifi;

        ifi = nfq_get_outdev(nfa);

		if (ifi)
		{
                nfq_get_outdev_name(nlif, nfa, netherPacket.outdevName);
        }
        else
		{
                strncpy(netherPacket.outdevName, "(unknown)", IFNAMSIZ);
                netherPacket.outdevName[IFNAMSIZ-1] = '\0';
        }
	}
}

int NetherNetlink::callback(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *nfa, void *data)
{
	NetherNetlink *me = static_cast<NetherNetlink *>(data);
	NetherPacket packet;
	unsigned char *secctx;
	int secctxSize = 0;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *payload;

	if((ph = nfq_get_msg_packet_hdr(nfa)))
	{
		packet.id = ntohl(ph->packet_id);
	}
	else
	{
		LOGI("Failed to get packet id");
		return (1);
	}

	/* get interface information if requested */
	me->getInterfaceInfo(nfa, packet);

	if(nfq_get_uid(nfa, &packet.uid) == 0)
		LOGW("Failed to get uid for packet id=" << packet.id);

	nfq_get_gid(nfa, &packet.gid);

	secctxSize = nfq_get_secctx(nfa, &secctx);

	if(secctxSize > 0)
		packet.securityContext = std::string((char *)secctx, secctxSize);
	else
		LOGD("Failed to get security context for packet id=" << packet.id);

	if(nfq_get_payload(nfa, &payload) > 0)
		decodePacket(packet, payload);

	me->processNetherPacket(packet);  /* this call if from the NetherPacketProcessor class */

	return (0);
}

void NetherNetlink::setVerdict(const u_int32_t packetId, const NetherVerdict verdict, int mark)
{
	int ret = 0;
	LOGD("id=" << packetId << " verdict=" << verdictToString(verdict) << " mark=" << mark);

	if(verdict == NetherVerdict::allow)
	{
		if (mark >= 0)
		{
			ret = nfq_set_verdict2(queueHandle,
								packetId,
								NF_ACCEPT,
								mark,
								0,
								NULL);
		}
		else
		{
			ret = nfq_set_verdict(queueHandle,
								packetId,
								NF_ACCEPT,
								0,
								NULL);
		}
	}

	if(verdict == NetherVerdict::deny)
	{
		ret = nfq_set_verdict2(queueHandle,
								packetId,
								NF_ACCEPT,
								/* if we're relaxed, let's not stress out */
								/* if we get a mark from the verdict caster */
								/* let's use it, maybe it knows better */
								mark > 0 ? mark : (netherConfig.relaxed ? netherConfig.markAllowAndLog : netherConfig.markDeny),
								0,
								NULL);
	}

	if(verdict == NetherVerdict::allowAndLog)
		ret = nfq_set_verdict2(queueHandle, packetId, NF_ACCEPT, netherConfig.markAllowAndLog, 0, NULL);

	if(ret == -1)
		LOGW("can't set verdict for packetId=" << packetId);
}

bool NetherNetlink::reload()
{
	return (true);
}

const NetherConfig &NetherNetlink::getNetherConfig()
{
	return (netherConfig);
}
