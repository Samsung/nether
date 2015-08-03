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
 * @brief   utility functions declarations
 */

#ifndef NETHER_UTILS_H
#define NETHER_UTILS_H

#include "nether_Types.h"

void decodePacket(NetherPacket &packet, unsigned char *payload);
void decodeIPv4Packet(NetherPacket &packet, unsigned char *payload);
void decodeIPv6Packet(NetherPacket &packet, unsigned char *payload);
void decodeTcp(NetherPacket &packet, unsigned char *payload);
void decodeUdp(NetherPacket &packet, unsigned char *payload);
std::string ipAddressToString(const char *src, enum NetherProtocolType type);

NetherVerdict stringToVerdict(char *verdictAsString);
NetherPolicyBackendType stringToBackendType(char *backendAsString);
NetherLogBackendType stringToLogBackendType(char *backendAsString);
std::string logBackendTypeToString(const NetherLogBackendType backendType);
std::string backendTypeToString(const NetherPolicyBackendType backendType);
std::string verdictToString(const NetherVerdict verdict);
std::string transportToString(const NetherTransportType transportType);
std::string protocolToString(const NetherProtocolType protocolType);
std::string packetToString(const NetherPacket &packet);
template<typename ... Args> std::string stringFormat(const char* format, Args ... args);

#endif // NETHER_UTILS_H
