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

CMAKE_MINIMUM_REQUIRED (VERSION 2.6)
PROJECT (nether)
INCLUDE (FindPkgConfig)

# Set compiler warning flags
ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings

IF (CMAKE_BUILD_TYPE MATCHES DEBUG)
	SET (CMAKE_CXX_FLAGS "-g -Wall -Wextra -std=c++11")
ELSE ()
	SET (CMAKE_CXX_FLAGS "-O3 -fomit-frame-pointer -std=c++11")
ENDIF (CMAKE_BUILD_TYPE MATCHES DEBUG)

SET (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

IF (NOT DEFINED SYSCONF_INSTALL_DIR)
    SET(SYSCONF_INSTALL_DIR "/etc")
ENDIF (NOT DEFINED SYSCONF_INSTALL_DIR)

IF (NOT DEFINED SYSTEMD_UNIT_DIR)
	SET(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
ENDIF (NOT DEFINED SYSTEMD_UNIT_DIR)


ADD_SUBDIRECTORY (src)
ADD_SUBDIRECTORY (conf)
