#ifndef NETHER_UTILS_H
#define NETHER_UTILS_H
#include "nether_Types.h"
void decodePacket(NetherPacket &packet, unsigned char *payload);
void decodeIPv4Packet(NetherPacket &packet, unsigned char *payload);
void decodeIPv6Packet(NetherPacket &packet, unsigned char *payload);
void decodeTcp(NetherPacket &packet, unsigned char *payload);
void decodeUdp(NetherPacket &packet, unsigned char *payload);
const std::string ipAddressToString(const char *src, enum NetherProtocolType type);

template <typename Type>
inline void deleteAndZero (Type& pointer)                           { delete pointer; pointer = nullptr; }

static const NetherVerdict stringToVerdict (char *verdictAsString)
{
    if (verdictAsString)
    {
        if (strncasecmp (verdictAsString, "allow_log", 9) == 0)
            return (allowAndLog);
        if (strncasecmp (verdictAsString, "allow", 6) == 0)
            return (allow);
        if (strncasecmp (verdictAsString, "deny", 4) == 0)
            return (deny);
    }
    return (allowAndLog);
}

static const NetherPolicyBackendType stringToBackendType (char *backendAsString)
{
    if (strcasecmp (backendAsString, "cynara") == 0)
      return (cynaraBackend);
    if (strcasecmp (backendAsString, "file") == 0)
      return (fileBackend);
    if (strcasecmp (backendAsString, "dummy") == 0)
      return (dummyBackend);

    return (dummyBackend);
}

static const NetherLogBackendType stringToLogBackendType(char *backendAsString)
{
    if (strcasecmp (backendAsString, "stderr") == 0)
      return (stderrBackend);
    if (strcasecmp (backendAsString, "syslog") == 0)
      return (syslogBackend);
    if (strcasecmp (backendAsString, "journal") == 0)
      return (journalBackend);
    if (strcasecmp (backendAsString, "file") == 0)
      return (logfileBackend);
    if (strcasecmp (backendAsString, "null") == 0)
      return (nullBackend);

    return (nullBackend);
}

static const std::string logBackendTypeToString(const NetherLogBackendType backendType)
{
    switch (backendType)
    {
        case stderrBackend:
            return ("stderr");
        case syslogBackend:
            return ("syslog");
        case journalBackend:
            return ("journal");
    case logfileBackend:
            return ("file");
        case nullBackend:
            return ("null");
    }
    return ("null");
}

static const std::string backendTypeToString (const NetherPolicyBackendType backendType)
{
    switch (backendType)
    {
        case cynaraBackend:
            return ("cynara");
        case fileBackend:
            return ("file");
        case dummyBackend:
        default:
            return ("dummy");
    }
}

static const std::string verdictToString (const NetherVerdict verdict)
{
    switch (verdict)
    {
        case allow:
            return ("ALLOW");
        case allowAndLog:
            return ("ALLOW_LOG");
        case deny:
            return ("DENY");
    }
}

static const std::string transportToString(const NetherTransportType transportType)
{
    switch (transportType)
    {
        case TCP:
            return ("TCP");
        case UDP:
            return ("UDP");
        case ICMP:
            return ("ICMP");
        case IGMP:
            return ("IGMP");
        case unknownTransportType:
        default:
            return ("UNKNOWN");
    }
}

static const std::string protocolToString(const NetherProtocolType protocolType)
{
    switch (protocolType)
    {
        case IPv4:
            return ("IPv4");
        case IPv6:
            return ("IPv6");
        default:
            return ("UNKNOWN");
    }
}

static const std::string packetToString (const NetherPacket &packet)
{
    std::stringstream stream;
    stream << "ID=";
    stream << packet.id;
    stream << " SECCTX=";
    stream << packet.securityContext;
    stream << " UID=";
    stream << packet.uid;
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

template<typename ... Args>
std::string stringFormat( const char* format, Args ... args )
{
    size_t size = snprintf( nullptr, 0, format, args ... ) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf( new char[ size ] );
    snprintf( buf.get(), size, format, args ... );
    return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
}
#endif
