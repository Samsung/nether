#
#  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#  Contact: Roman Kubiak (r.kubiak@samsung.com)
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License
#

FILE (GLOB NETHER_SOURCES *.cpp)
FILE (GLOB VASUM_LOGGER logger/*.cpp)

PKG_CHECK_MODULES (NETFILTER libnetfilter_queue REQUIRED)

IF (NOT DISABLE_CYNARA)
    PKG_CHECK_MODULES (CYNARA cynara-client-async)
endif()

IF (NOT DISABLE_SYSTEMD)
    PKG_CHECK_MODULES (SYSTEMD libsystemd-journal)
ENDIF()

IF (NOT DISABLE_AUDIT)
    FIND_PACKAGE(audit)
ENDIF()

IF (NOT DISABLE_BOOST)
    FIND_PACKAGE(Boost)
ENDIF()

ADD_EXECUTABLE(nether ${NETHER_SOURCES} ${VASUM_LOGGER})

IF (CMAKE_BUILD_TYPE MATCHES DEBUG)
	ADD_DEFINITIONS (-D_DEBUG=1)
ENDIF (CMAKE_BUILD_TYPE MATCHES DEBUG)

IF (CYNARA_FOUND)
	ADD_DEFINITIONS (-DHAVE_CYNARA=1)
ENDIF ()

IF (SYSTEMD_FOUND)
	ADD_DEFINITIONS (-DHAVE_SYSTEMD_JOURNAL=1)
ENDIF ()

IF (AUDIT_FOUND)
	ADD_DEFINITIONS (-DHAVE_AUDIT=1)
	INCLUDE_DIRECTORIES (${AUDIT_INCLUDE_DIR})
	TARGET_LINK_LIBRARIES (nether ${AUDIT_LIBRARY})
ENDIF ()

IF (Boost_FOUND)
	ADD_DEFINITIONS (-DHAVE_BOOST=1)
ENDIF ()

INCLUDE_DIRECTORIES(../include
	${CYNARA_INCLUDE_DIRS}
	${NETFILTER_INCLUDE_DIRS}
	${SYSTEMD_INCLUDE_DIRS}
)

TARGET_LINK_LIBRARIES (nether
	${CYNARA_LIBRARIES}
	${NETFILTER_LIBRARIES}
	${SYSTEMD_LIBRARIES}
)

ADD_DEFINITIONS (-DNETHER_RULES_PATH="${CMAKE_INSTALL_DIR}/etc/nether/nether.rules"
					-DNETHER_POLICY_FILE="${CMAKE_INSTALL_DIR}/etc/nether/nether.rules"
)

INSTALL (TARGETS nether RUNTIME DESTINATION bin)
