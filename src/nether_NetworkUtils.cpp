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
    uint8_t ip_version = (payload[0] >> 4) & 0x0F;

    switch(ip_version)
    {
        case 4:
            packet.protocolType     = IPv4;
            decodeIPv4Packet(packet, payload);
            break;
        case 6:
            packet.protocolType     = IPv6;
            decodeIPv6Packet(packet, payload);
            break;
        default:
            packet.transportType    = unknownTransportType;
            packet.protocolType     = unknownProtocolType;
            break;
    }
}

void decodeIPv6Packet(NetherPacket &packet, unsigned char *payload)
{
    const uint16_t start_of_ip_payload = 40;
    uint8_t next_proto;

    memcpy(packet.localAddress, &payload[8], NETHER_NETWORK_IPV6_ADDR_LEN);
    memcpy(packet.remoteAddress, &payload[24], NETHER_NETWORK_IPV6_ADDR_LEN);

    next_proto = payload[6];

    switch(next_proto)
    {
        case IP_PROTOCOL_UDP:
            packet.transportType = UDP;
            decodeUdp(packet, &payload[start_of_ip_payload]);
            break;
        case IP_PROTOCOL_TCP:
            packet.transportType = TCP;
            decodeTcp(packet, &payload[start_of_ip_payload]);
            break;
        case IP_PROTOCOL_ICMP:
            packet.transportType = ICMP;
            break;
        case IP_PROTOCOL_IGMP:
            packet.transportType = IGMP;
            break;
        default:
            packet.transportType = unknownTransportType;
            break;
    }
}

void decodeIPv4Packet(NetherPacket &packet, unsigned char *payload)
{
    uint16_t start_of_ip_payload = 0;
    uint8_t next_proto;

    start_of_ip_payload = (payload[0]&0x0F) << 2;

    memcpy(packet.localAddress, &payload[12], NETHER_NETWORK_IPV4_ADDR_LEN);
    memcpy(packet.remoteAddress, &payload[16], NETHER_NETWORK_IPV4_ADDR_LEN);

    next_proto = payload[9];
    switch(next_proto)
    {
        case IP_PROTOCOL_UDP:
            packet.transportType = UDP;
            decodeUdp(packet, &payload[start_of_ip_payload]);
            break;
        case IP_PROTOCOL_TCP:
            packet.transportType = TCP;
            decodeTcp(packet, &payload[start_of_ip_payload]);
            break;
        case IP_PROTOCOL_ICMP:
            packet.transportType = ICMP;
            break;
        case IP_PROTOCOL_IGMP:
            packet.transportType = IGMP;
        default:
            packet.transportType = unknownTransportType;
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
        case IPv4:
            return (stringFormat("%u.%u.%u.%u", src[0]&0xff,src[1]&0xff,src[2]&0xff,src[3]&0xff));
        case IPv6:
            return (stringFormat("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                            ntohs(*(uint16_t*) &src[0]), ntohs(*(uint16_t*) &src[2]),
                            ntohs(*(uint16_t*) &src[4]), ntohs(*(uint16_t*) &src[6]),
                            ntohs(*(uint16_t*) &src[8]), ntohs(*(uint16_t*) &src[10]),
                            ntohs(*(uint16_t*) &src[12]), ntohs(*(uint16_t*) &src[14])));
        default:
            return ("(unknown)");
    }
}
