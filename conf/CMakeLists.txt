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

MESSAGE(STATUS "Installing config files")

CONFIGURE_FILE(systemd/nether.service.in systemd/nether.service)

INSTALL(FILES nether.policy DESTINATION ${SYSCONF_INSTALL_DIR}/nether)
INSTALL(FILES nether.rules DESTINATION ${SYSCONF_INSTALL_DIR}/nether)
INSTALL(FILES systemd/nether.service DESTINATION ${SYSTEMD_UNIT_DIR})
INSTALL(FILES systemd/nether.service DESTINATION ${SYSTEMD_UNIT_DIR}/multi-user.target.wants)
