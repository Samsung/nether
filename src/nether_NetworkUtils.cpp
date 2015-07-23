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
 * @brief   Network utility functions for nether
 */

#include <netdb.h>
#include <linux/types.h>
#include "nether_Utils.h"

#define IP_PROTOCOL_UDP         (0x11)
#define IP_PROTOCOL_TCP         (0x06)
#define IP_PROTOCOL_ICMP        (0x01)
#define IP_PROTOCOL_IGMP        (0x02)
#define IP_PROTOCOL_IPV6_ROUTE  (0x2b)
#define IP_PROTOCOL_IPV6_FRAG   (0x2c)
#define IP_PROTOCOL_IPV6_ICMP   (0x3a)
#define IP_PROTOCOL_IPV6_NONXT  (0x3b)
#define IP_PROTOCOL_IPV6_OPTS   (0x3c)

void decodePacket(NetherPacket &packet, unsigned char *payload)
{
    uint8_t ipVersion = (payload[0] >> 4) & 0x0F;

    switch(ipVersion)
    {
        case 4:
            packet.protocolType     = NetherProtocolType::IPv4;
            decodeIPv4Packet(packet, payload);
            break;
        case 6:
            packet.protocolType     = NetherProtocolType::IPv6;
            decodeIPv6Packet(packet, payload);
            break;
        default:
            packet.transportType    = NetherTransportType::unknownTransportType;
            packet.protocolType     = NetherProtocolType::unknownProtocolType;
            break;
    }
}

void decodeIPv6Packet(NetherPacket &packet, unsigned char *payload)
{
    const uint16_t startOfIpPayload = 40;
    uint8_t nextProto;

    memcpy(packet.localAddress, &payload[8], NETHER_NETWORK_IPV6_ADDR_LEN);
    memcpy(packet.remoteAddress, &payload[24], NETHER_NETWORK_IPV6_ADDR_LEN);

    nextProto = payload[6];

    switch(nextProto)
    {
        case IP_PROTOCOL_UDP:
            packet.transportType = NetherTransportType::UDP;
            decodeUdp(packet, &payload[startOfIpPayload]);
            break;
        case IP_PROTOCOL_TCP:
            packet.transportType = NetherTransportType::TCP;
            decodeTcp(packet, &payload[startOfIpPayload]);
            break;
        case IP_PROTOCOL_ICMP:
            packet.transportType = NetherTransportType::ICMP;
            break;
        case IP_PROTOCOL_IGMP:
            packet.transportType = NetherTransportType::IGMP;
            break;
        default:
            packet.transportType = NetherTransportType::unknownTransportType;
            break;
    }
}

void decodeIPv4Packet(NetherPacket &packet, unsigned char *payload)
{
    uint16_t startOfIpPayload = 0;
    uint8_t nextProto;

    startOfIpPayload = (payload[0]&0x0F) << 2;

    memcpy(packet.localAddress, &payload[12], NETHER_NETWORK_IPV4_ADDR_LEN);
    memcpy(packet.remoteAddress, &payload[16], NETHER_NETWORK_IPV4_ADDR_LEN);

    nextProto = payload[9];

    switch(nextProto)
    {
        case IP_PROTOCOL_UDP:
            packet.transportType = NetherTransportType::UDP;
            decodeUdp(packet, &payload[startOfIpPayload]);
            break;
        case IP_PROTOCOL_TCP:
            packet.transportType = NetherTransportType::TCP;
            decodeTcp(packet, &payload[startOfIpPayload]);
            break;
        case IP_PROTOCOL_ICMP:
            packet.transportType = NetherTransportType::ICMP;
            break;
        case IP_PROTOCOL_IGMP:
            packet.transportType = NetherTransportType::IGMP;
        default:
            packet.transportType = NetherTransportType::unknownTransportType;
            break;
    }
}

void decodeTcp(NetherPacket &packet, unsigned char *payload)
{
    packet.localPort = ntohs(*(unsigned short*) &payload[0]);
    packet.remotePort = ntohs(*(unsigned short*) &payload[2]);
}

void decodeUdp(NetherPacket &packet, unsigned char *payload)
{
    packet.localPort = ntohs(*(unsigned short*) &payload[0]);
    packet.remotePort = ntohs(*(unsigned short*) &payload[2]);

}

const std::string ipAddressToString(const char *src, enum NetherProtocolType type)
{
    switch(type)
    {
        case NetherProtocolType::IPv4:
            return (stringFormat("%u.%u.%u.%u", src[0]&0xff,src[1]&0xff,src[2]&0xff,src[3]&0xff));
        case NetherProtocolType::IPv6:
            return (stringFormat("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                            ntohs(*(uint16_t*) &src[0]), ntohs(*(uint16_t*) &src[2]),
                            ntohs(*(uint16_t*) &src[4]), ntohs(*(uint16_t*) &src[6]),
                            ntohs(*(uint16_t*) &src[8]), ntohs(*(uint16_t*) &src[10]),
                            ntohs(*(uint16_t*) &src[12]), ntohs(*(uint16_t*) &src[14])));
        default:
            return ("(unknown)");
    }
}
